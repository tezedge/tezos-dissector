use tezos_messages::p2p::binary_message::BinaryChunk;
use wireshark_epan_adapter::dissector::{Tree, PacketInfo};
use failure::Fail;
use std::{convert::TryFrom, mem, task::Poll};
use crate::identity::{Identity, Decipher, NonceAddition};
use super::{
    addresses::{Addresses, Sender},
    connection_message::ConnectionMessage,
    chunk_buffer::ChunkBuffer,
};

pub struct Context {
    handshake: Handshake,
    from_initiator: ChunkBuffer,
    from_responder: ChunkBuffer,
    chunks_from_initiator: Vec<MaybePlain>,
    chunks_from_responder: Vec<MaybePlain>,
}

enum Handshake {
    Initial,
    IncomingBuffer {
        addresses: Addresses,
    },
    IncomingMessage {
        initiator_message: ConnectionMessage,
        addresses: Addresses,
    },
    BothMessages {
        initiator_message: ConnectionMessage,
        responder_message: ConnectionMessage,
        decipher: Option<Decipher>,
        addresses: Addresses,
    },
    Unrecognized,
}

#[derive(Debug, Fail)]
enum DecryptionError {
    #[fail(display = "wrong MAC")]
    WrongMac,
    #[fail(display = "identity needed")]
    HasNoIdentity,
}

enum MaybePlain {
    Error(BinaryChunk, DecryptionError),
    Connection(usize, ConnectionMessage),
    Plain(Vec<u8>),
}

impl MaybePlain {
    fn length(&self) -> usize {
        match self {
            &MaybePlain::Error(ref c, _) => c.content().len(),
            &MaybePlain::Connection(l, _) => l,
            &MaybePlain::Plain(ref d) => d.len() + 16, // MAC
        }
    }
}

struct HandshakeError;

impl Handshake {
    fn id(&self) -> String {
        match self {
            | &Handshake::Initial
            | &Handshake::Unrecognized=> format!("{:?}", self as *const _),
            | &Handshake::IncomingBuffer { ref addresses, .. }
            | &Handshake::IncomingMessage { ref addresses, .. }
            | &Handshake::BothMessages { ref addresses, .. } => format!("{:?}", addresses),
        }
    }

    fn initiator_message(
        from_initiator: &mut ChunkBuffer,
        payload: &[u8],
        frame_number: u64,
        addresses: Addresses,
    ) -> (Self, Poll<Result<Sender<Vec<MaybePlain>>, HandshakeError>>) {
        match from_initiator.consume(frame_number, payload) {
            Poll::Pending => (Handshake::IncomingBuffer { addresses }, Poll::Pending),
            Poll::Ready((0, mut chunks)) if chunks.len() == 1 => {
                let chunk = chunks.swap_remove(0);
                let length = chunk.content().len();
                match ConnectionMessage::try_from(chunk) {
                    Ok(initiator_message) => (
                        Handshake::IncomingMessage {
                            initiator_message: initiator_message.clone(),
                            addresses,
                        },
                        Poll::Ready(Ok(Sender::Initiator(vec![MaybePlain::Connection(length, initiator_message.clone())]))),
                    ),
                    Err(_) => (Handshake::Unrecognized, Poll::Ready(Err(HandshakeError))),
                }
            },
            _ => (Handshake::Unrecognized, Poll::Ready(Err(HandshakeError))),
        }
    }

    fn responder_message(
        from_responder: &mut ChunkBuffer,
        payload: &[u8],
        frame_number: u64,
        initiator_message: ConnectionMessage,
        addresses: Addresses,
        identity: Option<&Identity>,
    ) -> (Self, Poll<Result<Sender<Vec<MaybePlain>>, HandshakeError>>) {
        match from_responder.consume(frame_number, payload) {
            Poll::Pending => (Handshake::IncomingMessage { initiator_message, addresses }, Poll::Pending),
            Poll::Ready((0, mut chunks)) if chunks.len() == 1 => {
                let chunk = chunks.swap_remove(0);
                let length = chunk.content().len();
                match ConnectionMessage::try_from(chunk) {
                    Ok(responder_message) => {
                        let decipher = identity
                            .and_then(|i| i.decipher(&initiator_message, &responder_message));
                        (
                            Handshake::BothMessages {
                                initiator_message,
                                responder_message: responder_message.clone(),
                                decipher,
                                addresses,
                            },
                            Poll::Ready(Ok(Sender::Responder(vec![MaybePlain::Connection(length, responder_message.clone())]))),
                        )
                    },
                    Err(_) => (Handshake::Unrecognized, Poll::Ready(Err(HandshakeError))),
                }
            },
            _ => (Handshake::Unrecognized, Poll::Ready(Err(HandshakeError))),
        }
    }

    fn consume(
        &mut self,
        from_initiator: &mut ChunkBuffer,
        from_responder: &mut ChunkBuffer,
        payload: &[u8],
        packet_info: &PacketInfo,
        identity: Option<&Identity>,
    ) -> Poll<Result<Sender<Vec<MaybePlain>>, HandshakeError>> {
        let f = packet_info.frame_number();

        let c = mem::replace(self, Handshake::Unrecognized);
        let (c, r) = match c {
            Handshake::Initial => Handshake::initiator_message(from_initiator, payload, f, Addresses::new(packet_info)),
            Handshake::IncomingBuffer {
                addresses,
            } => match addresses.sender(packet_info) {
                Sender::Initiator(()) => Handshake::initiator_message(from_initiator, payload, f, addresses),
                Sender::Responder(()) => (Handshake::Unrecognized, Poll::Ready(Err(HandshakeError))),
            },
            Handshake::IncomingMessage {
                initiator_message,
                addresses,
            } => match addresses.sender(packet_info) {
                Sender::Initiator(()) => (Handshake::Unrecognized, Poll::Ready(Err(HandshakeError))),
                Sender::Responder(()) => Handshake::responder_message(from_responder, payload, f, initiator_message, addresses, identity),
            },
            Handshake::BothMessages {
                initiator_message,
                responder_message,
                decipher,
                addresses,
            } => {
                let sender = addresses.sender(packet_info);
                let buffer = match sender {
                    Sender::Initiator(()) => from_initiator,
                    Sender::Responder(()) => from_responder,
                };
                let r = buffer
                    .consume(f, payload)
                    .map(|(nonce, chunks)| {
                        chunks
                            .into_iter()
                            .enumerate()
                            .map(|(i, chunk)| {
                                match decipher.as_ref() {
                                    None => MaybePlain::Error(chunk, DecryptionError::HasNoIdentity),
                                    Some(d) => {
                                        let i = i as u64;
                                        // first message is connection message (plain)
                                        let nonce = nonce - 1;
                                        let nonce = match &sender {
                                            &Sender::Initiator(()) => NonceAddition::Initiator(nonce + i),
                                            &Sender::Responder(()) => NonceAddition::Responder(nonce + i),
                                        };
                                        match d.decrypt(chunk.content(), nonce) {
                                            Ok(data) => MaybePlain::Plain(data),
                                            Err(e) => {
                                                log::error!("{:?}, {:?}", addresses, e);
                                                MaybePlain::Error(chunk, DecryptionError::WrongMac)
                                            },
                                        }
                                    },
                                }
                            })
                            .collect()
                    })
                    .map(|m| Ok(sender.map(|()| m)));
                (
                    Handshake::BothMessages {
                        initiator_message,
                        responder_message,
                        decipher,
                        addresses,
                    },
                    r,
                )
            },
            Handshake::Unrecognized => (Handshake::Unrecognized, Poll::Ready(Err(HandshakeError))),
        };
        let _ = mem::replace(self, c);
        r
    }
}

impl Context {
    pub fn invalid(&self) -> bool {
        match &self.handshake {
            &Handshake::Unrecognized => true,
            _ => false,
        }
    }

    pub fn consume(&mut self, payload: &[u8], packet_info: &PacketInfo, identity: Option<&Identity>) {
        match self.handshake.consume(&mut self.from_initiator, &mut self.from_responder, payload, packet_info, identity) {
            Poll::Ready(Ok(Sender::Initiator(mut m))) => self.chunks_from_initiator.append(&mut m),
            Poll::Ready(Ok(Sender::Responder(mut m))) => self.chunks_from_responder.append(&mut m),
            _ => (),
        }
    }

    pub fn id(&self) -> String {
        self.handshake.id()
    }

    pub fn visualize(&mut self, payload: &[u8], packet_info: &PacketInfo, root: &mut Tree) {
        use wireshark_epan_adapter::dissector::TreeLeaf;

        let mut main = root.add("tezos", 0..payload.len(), TreeLeaf::nothing()).subtree();
        main.add("conversation_id", 0..0, TreeLeaf::Display(self.id()));

        let f = packet_info.frame_number();
        let i = self.from_initiator.frames_description(f);
        let r = self.from_responder.frames_description(f);
        let (caption, messages, first_offset, last_offset) = match (i, r) {
            (Some(_), Some(_)) => panic!(),
            (None, None) => panic!(),
            (Some(range), None) => (
                "from initiator",
                &self.chunks_from_initiator[(range.start.index as usize)..(range.end.index as usize)],
                range.start.offset as usize,
                range.end.offset as usize,
            ),
            (None, Some(range)) => (
                "from responder",
                &self.chunks_from_responder[(range.start.index as usize)..(range.end.index as usize)],
                range.start.offset as usize,
                range.end.offset as usize,
            ),
        };
        main.add("direction", 0..0, TreeLeaf::Display(caption));

        let mut offset = 0;
        for (i, message) in messages.iter().enumerate() {
            let chunk_header_range = match i {
                // first chunk in the packet
                0 => {
                    let r = if first_offset < 2 {
                        Some(0..(2 - first_offset))
                    } else {
                        None
                    };
                    offset += message.length() - first_offset + 2;
                    r
                },
                // middle chunk in the packet
                l if l < messages.len() - 1 => {
                    let r = Some(offset..(offset + 2));
                    offset += message.length() + 2;
                    r
                },
                // last chunk in the packet
                l if l == messages.len() - 1 => if last_offset == 0 {
                    let r = Some(offset..(offset + 2));
                    offset += message.length() + 2;
                    r
                } else {
                    Some(offset..(offset + usize::min(2, last_offset)))
                },
                _ => panic!(),
            };
            let header_end = chunk_header_range.clone().unwrap_or(0..0).end;
            if let Some(range) = chunk_header_range {
                main.add("chunk_length", range, TreeLeaf::dec(message.length() as _));
            }
            let body_end = header_end + message.length() - 16;
            let body_upper_bound = usize::min(payload.len(), body_end);
            let body_range = header_end..body_upper_bound;
            let mac_upper_bound = usize::min(payload.len(), body_end + 16);
            let mac_range = body_upper_bound..mac_upper_bound;
            match message {
                &MaybePlain::Error(ref chunk, DecryptionError::HasNoIdentity) => {
                    main.add("identity_required", body_range, TreeLeaf::Display(format!("encrypted: {}", hex::encode(chunk.content()))));
                },
                &MaybePlain::Error(ref chunk, DecryptionError::WrongMac) => {
                    main.add("error", body_range, TreeLeaf::Display(format!("encrypted: {}", hex::encode(chunk.content()))));
                },
                &MaybePlain::Connection(_, ref connection) => {
                    main.show(connection, &[]);
                },
                &MaybePlain::Plain(ref plain) => {
                    main.add("decrypted_data", body_range, TreeLeaf::Display(hex::encode(plain)));
                },
            }
            main.add("mac", mac_range, TreeLeaf::Display(""));
        }
    }
}

impl Default for Context {
    fn default() -> Self {
        Context {
            handshake: Handshake::Initial,
            from_initiator: ChunkBuffer::new(),
            from_responder: ChunkBuffer::new(),
            chunks_from_initiator: Vec::new(),
            chunks_from_responder: Vec::new(),
        }
    }
}
