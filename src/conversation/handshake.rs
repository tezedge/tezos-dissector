use wireshark_epan_adapter::dissector::PacketInfo;
use tezos_messages::p2p::binary_message::BinaryChunk;
use failure::Fail;
use std::{task::Poll, convert::TryFrom};
use super::{Addresses, ConnectionMessage, ChunkBuffer, Sender};
use crate::identity::{Identity, NonceAddition, Decipher};

pub enum Handshake {
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
pub enum DecryptionError {
    #[fail(display = "wrong MAC")]
    WrongMac,
    #[fail(display = "identity needed")]
    HasNoIdentity,
}

pub enum MaybePlain {
    Error(BinaryChunk, DecryptionError),
    Connection(usize, ConnectionMessage),
    Plain(Vec<u8>),
}

impl MaybePlain {
    pub fn length(&self) -> usize {
        match self {
            &MaybePlain::Error(ref c, _) => c.content().len(),
            &MaybePlain::Connection(l, _) => l,
            &MaybePlain::Plain(ref d) => d.len() + 16, // MAC
        }
    }
}

pub struct HandshakeError;

impl Handshake {
    pub fn id(&self) -> String {
        match self {
            &Handshake::Initial | &Handshake::Unrecognized => format!("{:?}", self as *const _),
            &Handshake::IncomingBuffer { ref addresses, .. }
            | &Handshake::IncomingMessage { ref addresses, .. }
            | &Handshake::BothMessages { ref addresses, .. } => format!("{:?}", addresses),
        }
    }

    pub fn initiator_message(
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

    pub fn responder_message(
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

    pub fn consume(
        &mut self,
        from_initiator: &mut ChunkBuffer,
        from_responder: &mut ChunkBuffer,
        payload: &[u8],
        packet_info: &PacketInfo,
        identity: Option<&Identity>,
    ) -> Poll<Result<Sender<Vec<MaybePlain>>, HandshakeError>> {
        use std::mem;

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
