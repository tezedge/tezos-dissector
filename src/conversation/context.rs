use tezos_messages::p2p::binary_message::BinaryChunk;
use wireshark_epan_adapter::dissector::{Tree, PacketInfo, SocketAddress};
use crypto::crypto_box::CryptoError;
use std::{convert::TryFrom, mem, task::Poll};
use crate::identity::{Identity, Decipher, NonceAddition};
use super::{connection_message::ConnectionMessage, chunk_buffer::ChunkBuffer};

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
                match ConnectionMessage::try_from(chunk) {
                    Ok(initiator_message) => (
                        Handshake::IncomingMessage {
                            initiator_message: initiator_message.clone(),
                            addresses,
                        },
                        Poll::Ready(Ok(Sender::Initiator(vec![MaybePlain::Connection(initiator_message.clone())]))),
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
                            Poll::Ready(Ok(Sender::Responder(vec![MaybePlain::Connection(responder_message.clone())]))),
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
                                    None => MaybePlain::RequiredIdentity(chunk),
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
                                                MaybePlain::Error(chunk, e)
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
        let (caption, messages, _first_offset, _last_offset) = match (i, r) {
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

        for (_i, message) in messages.iter().enumerate() {
            /*let chunk_header_range = match i {
                // first chunk in the packet
                0 => if first_offset < 2 {
                    Some(first_offset..2)
                } else {
                    None
                },
                // middle chunk in the packet
                l if l < messages.len() - 1 => Some(0..2),
                // last chunk in the packet
                l if l == messages.len() - 1 => if last_offset >= 2 {
                    Some(0..last_offset)
                } else {
                    None
                },
                _ => None,
            };*/
            match message {
                &MaybePlain::RequiredIdentity(ref chunk) => {
                    main.add("identity_required", 0..0, TreeLeaf::Display(format!("{}, encrypted {}", caption, hex::encode(chunk.content()))));
                },
                &MaybePlain::Error(ref chunk, ref error) => {
                    main.add("error", 0..0, TreeLeaf::Display(format!("{}, error: {}, encrypted {}", caption, error, hex::encode(chunk.content()))));
                },
                &MaybePlain::Connection(ref connection) => {
                    main.show(connection, &[]);
                },
                &MaybePlain::Plain(ref plain) => {
                    main.add("decrypted_data", 0..0, TreeLeaf::Display(format!("{}: {}", caption, hex::encode(plain))));
                },
            }
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
