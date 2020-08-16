use tezos_messages::p2p::binary_message::{BinaryChunk, BinaryChunkError};
use wireshark_epan_adapter::dissector::{Tree, PacketInfo};
use std::{
    net::SocketAddr,
    convert::TryFrom,
    mem,
};
use crate::network::prelude::{ConnectionMessage, EncryptedMessageDecoder};
use super::identity::Identity;

pub enum Context {
    Initial,
    IncomingBuffer {
        incoming_data: Vec<u8>,
        addresses: (SocketAddr, SocketAddr),
    },
    IncomingMessage {
        incoming_frame_number: u64,
        incoming_message: ConnectionMessage,
        outgoing_data: Vec<u8>,
        addresses: (SocketAddr, SocketAddr),
    },
    BothMessages {
        incoming_frame_number: u64,
        outgoing_frame_number: u64,
        incoming_message: ConnectionMessage,
        outgoing_message: ConnectionMessage,
        addresses: (SocketAddr, SocketAddr),
        cache_decipher: Option<(EncryptedMessageDecoder, EncryptedMessageDecoder)>,
    },
    Unrecognized,
}

impl Context {
    pub fn invalid(&self) -> bool {
        match self {
            &Context::Unrecognized => true,
            _ => false,
        }
    }

    pub fn consume(&mut self, payload: &[u8], packet_info: &PacketInfo) {
        let current_frame_number = packet_info.frame_number();

        let c = mem::replace(self, Context::Unrecognized);
        let c = match c {
            Context::Initial => {
                match (packet_info.source(), packet_info.destination()) {
                    (Ok(initiator), Ok(responder)) => {
                        // Hope, rust backend is smart enough to optimize it
                        // and do not do allocation in case of error
                        match BinaryChunk::try_from(payload.to_owned()) {
                            Ok(chunk) => match ConnectionMessage::try_from(chunk) {
                                Ok(message) => Context::IncomingMessage {
                                    incoming_frame_number: current_frame_number,
                                    incoming_message: message,
                                    outgoing_data: Vec::new(),
                                    addresses: (initiator, responder),
                                },
                                Err(_) => Context::Unrecognized,
                            },
                            Err(BinaryChunkError::IncorrectSizeInformation { .. }) => {
                                Context::IncomingBuffer {
                                    incoming_data: payload.to_owned(),
                                    addresses: (initiator, responder),
                                }
                            },
                            Err(_) => Context::Unrecognized,
                        }
                    },
                    (Err(e), Ok(_)) => {
                        log::error!("Failed to retrieve initiator address: {:?}", e);
                        Context::Unrecognized
                    },
                    (Ok(_), Err(e)) => {
                        log::error!("Failed to retrieve responder address: {:?}", e);
                        Context::Unrecognized
                    },
                    (Err(ei), Err(er)) => {
                        log::error!("Failed to retrieve initiator address: {:?}", ei);
                        log::error!("Failed to retrieve responder address: {:?}", er);
                        Context::Unrecognized
                    },
                }
            },
            Context::IncomingBuffer {
                mut incoming_data,
                addresses: (initiator, responder),
            } => {
                match packet_info.source() {
                    Ok(source) if source == initiator => {
                        incoming_data.extend_from_slice(payload);
                        match BinaryChunk::try_from(incoming_data.clone()) {
                            Ok(chunk) => match ConnectionMessage::try_from(chunk) {
                                Ok(incoming_message) => Context::IncomingMessage {
                                    incoming_frame_number: current_frame_number,
                                    incoming_message,
                                    outgoing_data: Vec::new(),
                                    addresses: (initiator, responder),
                                },
                                Err(_) => Context::Unrecognized,
                            },
                            Err(BinaryChunkError::IncorrectSizeInformation { .. }) => {
                                Context::IncomingBuffer {
                                    incoming_data: payload.to_owned(),
                                    addresses: (initiator, responder),
                                }
                            },
                            Err(_) => Context::Unrecognized,
                        }
                    },
                    _ => Context::Unrecognized,
                }
            },
            Context::IncomingMessage {
                incoming_frame_number,
                incoming_message,
                mut outgoing_data,
                addresses: (initiator, responder),
            } => {
                match packet_info.destination() {
                    Ok(destination) if destination == initiator => {
                        outgoing_data.extend_from_slice(payload);
                        match BinaryChunk::try_from(outgoing_data.clone()) {
                            Ok(chunk) => match ConnectionMessage::try_from(chunk) {
                                Ok(outgoing_message) => Context::BothMessages {
                                    incoming_frame_number,
                                    outgoing_frame_number: current_frame_number,
                                    incoming_message,
                                    outgoing_message,
                                    addresses: (initiator, responder),
                                    cache_decipher: None,
                                },
                                Err(_) => Context::Unrecognized,
                            },
                            Err(BinaryChunkError::IncorrectSizeInformation { .. }) => {
                                Context::IncomingMessage {
                                    incoming_frame_number,
                                    incoming_message,
                                    outgoing_data,
                                    addresses: (initiator, responder),
                                }
                            },
                            Err(_) => Context::Unrecognized,
                        }
                    },
                    _ => Context::Unrecognized,
                }
            },
            t => t,
        };
        let _ = mem::replace(self, c);
    }

    fn incoming_connection(&self) -> Option<(u64, &ConnectionMessage)> {
        match self {
            | &Context::IncomingMessage { incoming_frame_number: n, incoming_message: ref m, .. }
            | &Context::BothMessages { incoming_frame_number: n, incoming_message: ref m, .. } => Some((n, m)),
            _ => None,
        }
    }

    fn outgoing_connection(&self) -> Option<(u64, &ConnectionMessage)> {
        match self {
            | &Context::BothMessages { outgoing_frame_number: n, outgoing_message: ref m, .. } => Some((n, m)),
            _ => None,
        }
    }

    pub fn try_decipher(&mut self, identity: &Identity) {
        match self {
            &mut Context::BothMessages {
                incoming_frame_number: _,
                outgoing_frame_number: _,
                ref incoming_message,
                ref outgoing_message,
                addresses: _,
                ref mut cache_decipher,
            } => {
                if cache_decipher.is_none() {
                    *cache_decipher = identity.decipher_pair(incoming_message, outgoing_message);
                }
            },
            _ => (),
        }
    }

    pub fn visualize(
        &mut self,
        payload: &[u8],
        packet_info: &PacketInfo,
        root: &mut Tree,
        identity: &Option<Identity>,
    ) {
        use wireshark_epan_adapter::dissector::TreeLeaf;

        fn show_connection_message(m: &ConnectionMessage, tree: &mut Tree, l: usize) {
            tree.add("port", 0..2, TreeLeaf::dec(m.port as _));
            tree.add("pk", 2..34, TreeLeaf::Display(hex::encode(&m.public_key)));
            tree.add("pow", 34..58, TreeLeaf::Display(hex::encode(&m.proof_of_work_stamp)));
            tree.add("nonce", 58..82, TreeLeaf::Display(hex::encode(&m.message_nonce)));
            tree.add("version", 82..l, TreeLeaf::Display(format!("{:?}", m.versions)));
        }

        let mut main = root.add("tezos", 0..payload.len(), TreeLeaf::nothing()).subtree();
        main.add("conversation_id", 0..0, TreeLeaf::Display(format!("{:?}", self as *mut _)));

        let l = payload.len();
        let f = packet_info.frame_number();
        if let Some((n, m)) = self.incoming_connection() {
            if f < n {
                main.add("connection_msg", 0..l, TreeLeaf::Display("from initiator incomplete"));
            } else if f == n {
                main.add("chunk_length", 0..2, TreeLeaf::dec((l - 2) as _));
                let mut msg_tree = main.add("connection_msg", 2..l, TreeLeaf::Display("from initiator"))
                    .subtree();
                show_connection_message(m, &mut msg_tree, l - 2);
            } else {
                if let Some((n, m)) = self.outgoing_connection() {
                    if f < n {
                        main.add("connection_msg", 0..l, TreeLeaf::Display("from responder incomplete"));
                    } else if f == n {
                        main.add("chunk_length", 0..2, TreeLeaf::dec((l - 2) as _));
                        let mut msg_tree = main.add("connection_msg", 2..l, TreeLeaf::Display("from responder"))
                            .subtree();
                        show_connection_message(m, &mut msg_tree, l - 2);
                    } else if f > n {
                        if let &Some(ref identity) = identity {
                            self.visualize_decrypted(identity, payload, packet_info, &mut main, l);
                        } else {
                            main.add("decrypted_msg", 0..l, TreeLeaf::Display("encrypted message"));
                        }
                    }
                }
            }
        }
    }

    pub fn visualize_decrypted(
        &mut self,
        identity: &Identity,
        payload: &[u8],
        packet_info: &PacketInfo,
        root: &mut Tree,
        l: usize,
    ) {
        use wireshark_epan_adapter::dissector::TreeLeaf;

        self.try_decipher(identity);
        match self {
            &mut Context::BothMessages {
                cache_decipher: Some( (ref mut receiving, ref mut sending)),
                ..
            } => {
                // TODO:
                let _ = (payload, packet_info, root, receiving, sending);
            },
            _ => {
                root.add("decrypted_msg", 0..l, TreeLeaf::Display("identity required to decrypt"));
            },
        }
    }
}

impl Default for Context {
    fn default() -> Self {
        Context::Initial
    }
}
