use tezos_messages::p2p::binary_message::BinaryChunk;
use wireshark_epan_adapter::dissector::{Tree, PacketInfo, SocketAddress};
use crypto::crypto_box::CryptoError;
use std::{
    convert::TryFrom,
    mem,
};
use crate::identity::{Identity, Decipher, NonceAddition};
use super::{
    connection_message::ConnectionMessage,
    buffering_result::BufferingResult,
    chunk_buffer::{ChunkBuffer, ChunkBufferError},
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

#[derive(Debug)]
struct Addresses {
    initiator: SocketAddress,
    responder: SocketAddress,
}

impl Addresses {
    fn new(packet_info: &PacketInfo) -> Self {
        Addresses {
            initiator: packet_info.source(),
            responder: packet_info.destination(),
        }
    }

    fn sender(&self, packet_info: &PacketInfo) -> Sender<()> {
        if self.initiator == packet_info.source() {
            assert_eq!(self.responder, packet_info.destination());
            Sender::Initiator(())
        } else if self.responder == packet_info.source() {
            assert_eq!(self.initiator, packet_info.destination());
            Sender::Responder(())
        } else {
            panic!()
        }
    }
}

#[derive(Eq, PartialEq)]
pub enum Sender<T> {
    Initiator(T),
    Responder(T),
}

impl<T> Sender<T> {
    fn map<F, U>(self, op: F) -> Sender<U>
    where
        F: FnOnce(T) -> U,
    {
        match self {
            Sender::Initiator(t) => Sender::Initiator(op(t)),
            Sender::Responder(t) => Sender::Responder(op(t)),
        }
    }
}

enum MaybePlain {
    RequiredIdentity(BinaryChunk),
    Error(BinaryChunk, CryptoError),
    Connection(ConnectionMessage),
    Plain(Vec<u8>),
}

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

    fn consume(
        &mut self,
        from_initiator: &mut ChunkBuffer,
        from_responder: &mut ChunkBuffer,
        payload: &[u8],
        packet_info: &PacketInfo,
        identity: Option<&Identity>,
    ) -> BufferingResult<Sender<MaybePlain>, ChunkBufferError> {
        let f = packet_info.frame_number();

        let c = mem::replace(self, Handshake::Unrecognized);
        let mut r = BufferingResult::Buffering;
        let c = match c {
            Handshake::Initial => {
                match from_initiator.consume(f, payload) {
                    BufferingResult::Ready(chunk) => match ConnectionMessage::try_from(chunk) {
                        Ok(initiator_message) => {
                            r = BufferingResult::Ready(Sender::Initiator(MaybePlain::Connection(initiator_message.clone())));
                            Handshake::IncomingMessage {
                                initiator_message,
                                addresses: Addresses::new(packet_info),
                            }
                        },
                        Err(_) => Handshake::Unrecognized,
                    },
                    BufferingResult::Buffering => Handshake::IncomingBuffer {
                        addresses: Addresses::new(packet_info),
                    },
                    BufferingResult::Unrecognized(_e) => Handshake::Unrecognized,
                }
            },
            Handshake::IncomingBuffer {
                addresses,
            } => match addresses.sender(packet_info) {
                Sender::Initiator(()) => match from_initiator.consume(f, payload) {
                    BufferingResult::Ready(chunk) => match ConnectionMessage::try_from(chunk) {
                        Ok(initiator_message) => {
                            r = BufferingResult::Ready(Sender::Initiator(MaybePlain::Connection(initiator_message.clone())));
                            Handshake::IncomingMessage {
                                initiator_message,
                                addresses,
                            }
                        },
                        Err(_) => Handshake::Unrecognized,
                    },
                    BufferingResult::Buffering => Handshake::IncomingBuffer { addresses },
                    BufferingResult::Unrecognized(_e) => Handshake::Unrecognized,
                },
                Sender::Responder(()) => Handshake::Unrecognized,
            },
            Handshake::IncomingMessage {
                initiator_message,
                addresses,
            } => match addresses.sender(packet_info) {
                Sender::Initiator(()) => Handshake::Unrecognized,
                Sender::Responder(()) => match from_responder.consume(f, payload) {
                    BufferingResult::Ready(chunk) => match ConnectionMessage::try_from(chunk) {
                        Ok(responder_message) => {
                            r = BufferingResult::Ready(Sender::Responder(MaybePlain::Connection(responder_message.clone())));
                            let decipher = identity
                                .and_then(|i| i.decipher(&initiator_message, &responder_message));
                            Handshake::BothMessages {
                                initiator_message,
                                responder_message,
                                decipher,
                                addresses,
                            }
                        },
                        Err(_) => Handshake::Unrecognized,
                    },
                    BufferingResult::Buffering => Handshake::IncomingMessage { initiator_message, addresses },
                    BufferingResult::Unrecognized(_e) => Handshake::Unrecognized,
                }
            },
            Handshake::BothMessages {
                initiator_message,
                responder_message,
                decipher,
                addresses,
            } => {
                let (index, buffer) = match addresses.sender(packet_info) {
                    Sender::Initiator(()) => (NonceAddition::Initiator(from_initiator.last_chunks_index() - 1), from_initiator),
                    Sender::Responder(()) => (NonceAddition::Responder(from_responder.last_chunks_index() - 1), from_responder),
                };
                r = buffer
                    .consume(f, payload)
                    .or(|e| {
                        log::error!("{:?} buffer overflow at {:?}", addresses, e);
                        BufferingResult::Unrecognized(e)
                    })
                    .map(|chunk| {
                        match decipher.as_ref() {
                            None => MaybePlain::RequiredIdentity(chunk),
                            Some(d) => match d.decrypt(chunk.content(), index) {
                                Ok(data) => MaybePlain::Plain(data),
                                Err(e) => {
                                    log::error!("{:?}, {:?}", addresses, e);
                                    MaybePlain::Error(chunk, e)
                                },
                            }
                        }
                    })
                    .map(|m| addresses.sender(packet_info).map(|()| m));
                Handshake::BothMessages {
                    initiator_message,
                    responder_message,
                    decipher,
                    addresses,
                }
            },
            Handshake::Unrecognized => Handshake::Unrecognized,
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
            BufferingResult::Ready(Sender::Initiator(m)) => self.chunks_from_initiator.push(m),
            BufferingResult::Ready(Sender::Responder(m)) => self.chunks_from_responder.push(m),
            _ => (),
        }
    }

    pub fn id(&self) -> String {
        self.handshake.id()
    }

    pub fn visualize(
        &mut self,
        payload: &[u8],
        packet_info: &PacketInfo,
        root: &mut Tree,
    ) {
        use wireshark_epan_adapter::dissector::TreeLeaf;
        use bytes::Buf;

        fn show_connection_message(m: &ConnectionMessage, tree: &mut Tree, l: usize) {
            // TODO: ranges
            tree.add("port", 0..2, TreeLeaf::dec(m.port as _));
            tree.add("pk", 2..34, TreeLeaf::Display(hex::encode(&m.public_key)));
            tree.add("pow", 34..58, TreeLeaf::Display(hex::encode(&m.proof_of_work_stamp)));
            tree.add("nonce", 58..82, TreeLeaf::Display(hex::encode(&m.message_nonce)));
            tree.add("version", 82..l, TreeLeaf::Display(format!("{:?}", m.versions)));
        }

        let mut main = root.add("tezos", 0..payload.len(), TreeLeaf::nothing()).subtree();
        main.add("conversation_id", 0..0, TreeLeaf::Display(self.id()));
        let l = payload.len();

        let f = packet_info.frame_number();
        let i = self.from_initiator.chunk_index(f);
        let r = self.from_responder.chunk_index(f);
        let (caption, message, index) = match (i, r) {
            (Some(_), Some(_)) => panic!(),
            (None, None) => return,
            (Some(index), None) => (
                "from initiator",
                self.chunks_from_initiator.get(index.index as usize),
                index,
            ),
            (None, Some(index)) => (
                "from responder",
                self.chunks_from_responder.get(index.index as usize),
                index,
            ),
        };

        let b = if index.offset == 0 {
            let l = (&payload[0..2]).get_u16();
            main.add("chunk_length", 0..2, TreeLeaf::dec(l as _));
            2
        } else {
            0
        };

        match message {
            None => {
                main.add("buffering", b..l, TreeLeaf::Display(format!("{}", caption)));
            }
            Some(&MaybePlain::RequiredIdentity(ref chunk)) => {
                let _ = chunk;
                main.add("identity_required", b..l, TreeLeaf::Display(format!("{}, encrypted {}", caption, hex::encode(chunk.content()))));
            },
            Some(&MaybePlain::Error(ref chunk, ref error)) => {
                main.add("error", b..l, TreeLeaf::Display(format!("{}, error: {}, encrypted {}", caption, error, hex::encode(chunk.content()))));
            },
            Some(&MaybePlain::Connection(ref connection)) => {
                let mut msg_tree = main.add("connection_msg", b..l, TreeLeaf::Display(caption)).subtree();
                show_connection_message(connection, &mut msg_tree, l - 2);
            },
            Some(&MaybePlain::Plain(ref plain)) => {
                main.add("decrypted_msg", b..l, TreeLeaf::Display(format!("{}: {}", caption, hex::encode(plain))));
            },
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
