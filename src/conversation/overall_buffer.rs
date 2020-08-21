use wireshark_epan_adapter::dissector::{PacketInfo, Tree, TreeLeaf};
use std::ops::Range;
use tezos_encoding::encoding::HasEncoding;
use tezos_messages::p2p::encoding::{metadata::MetadataMessage, peer::PeerMessageResponse};
use super::{
    Addresses, Sender,
    DirectBuffer,
    ConnectionMessage,
};
use crate::{
    identity::{Decipher, Identity, NonceAddition},
    value::{show, Named},
};

pub enum Context {
    Empty,
    Handshake(ConversationBuffer, Option<Decipher>),
    Unrecognized,
}

pub struct ConversationBuffer {
    addresses: Addresses,
    incoming_decrypted: usize,
    incoming: DirectBuffer,
    outgoing_decrypted: usize,
    outgoing: DirectBuffer,
}

impl ConversationBuffer {
    fn consume(&mut self, payload: &[u8], packet_info: &PacketInfo) {
        match self.addresses.sender(packet_info) {
            Sender::Initiator(()) => self.incoming.consume(payload, packet_info.frame_number()),
            Sender::Responder(()) => self.outgoing.consume(payload, packet_info.frame_number()),
        }
    }

    fn can_upgrade(&self) -> bool {
        match (self.incoming.chunks().first(), self.outgoing.chunks().first()) {
            (Some(i), Some(o)) => {
                self.incoming.data().len() >= i.end && self.outgoing.data().len() > o.end
            },
            _ => false,
        }
    }

    fn data(&self, packet_info: &PacketInfo) -> &[u8] {
        match self.addresses.sender(packet_info) {
            Sender::Initiator(()) => self.incoming.data(),
            Sender::Responder(()) => self.outgoing.data(),
        }
    }

    fn chunks(&self, packet_info: &PacketInfo) -> &[Range<usize>] {
        match self.addresses.sender(packet_info) {
            Sender::Initiator(()) => self.incoming.chunks(),
            Sender::Responder(()) => self.outgoing.chunks(),
        }
    }

    fn packet(&self, packet_info: &PacketInfo) -> Range<usize> {
        match self.addresses.sender(packet_info) {
            Sender::Initiator(()) => self.incoming.packet(packet_info.frame_number()),
            Sender::Responder(()) => self.outgoing.packet(packet_info.frame_number()),
        }
    }

    fn decrypted(&self, packet_info: &PacketInfo) -> usize {
        match self.addresses.sender(packet_info) {
            Sender::Initiator(()) => self.incoming_decrypted,
            Sender::Responder(()) => self.outgoing_decrypted,
        }
    }
}

impl Context {
    pub fn consume(&mut self, payload: &[u8], packet_info: &PacketInfo, identity: Option<&Identity>) {
        match self {
            &mut Context::Empty => {
                let mut incoming = DirectBuffer::new();
                incoming.consume(payload, packet_info.frame_number());
                *self = Context::Handshake(
                    ConversationBuffer {
                        addresses: Addresses::new(packet_info),
                        incoming_decrypted: 1,
                        incoming,
                        outgoing_decrypted: 1,
                        outgoing: DirectBuffer::new(),
                    },
                    None,
                );
            },
            &mut Context::Handshake(ref mut buffer, ref mut decipher) => {
                buffer.consume(payload, packet_info);
                if let &mut Some(ref decipher) = decipher {
                    if buffer.incoming.chunks().len() > buffer.incoming_decrypted {
                        let chunks = (&buffer.incoming.chunks()[buffer.incoming_decrypted..]).to_vec();
                        for chunk in chunks {
                            if buffer.incoming.data().len() >= chunk.end {
                                let nonce = NonceAddition::Initiator((buffer.incoming_decrypted - 1) as u64);
                                buffer.incoming_decrypted += 1;
                                let data = &buffer.incoming.data()[(chunk.start + 2)..chunk.end];
                                if let Ok(plain) = decipher.decrypt(data, nonce) {
                                    buffer.incoming.data_mut()[(chunk.start + 2)..(chunk.end - 16)].clone_from_slice(plain.as_ref());
                                }
                            } else {
                                break
                            }
                        }
                    }
                    if buffer.outgoing.chunks().len() > buffer.outgoing_decrypted {
                        let chunks = (&buffer.outgoing.chunks()[buffer.outgoing_decrypted..]).to_vec();
                        for chunk in chunks {
                            if buffer.outgoing.data().len() >= chunk.end {
                                let nonce = NonceAddition::Responder((buffer.outgoing_decrypted - 1) as u64);
                                buffer.outgoing_decrypted += 1;
                                let data = &buffer.outgoing.data()[(chunk.start + 2)..chunk.end];
                                if let Ok(plain) = decipher.decrypt(data, nonce) {
                                    buffer.outgoing.data_mut()[(chunk.start + 2)..(chunk.end - 16)].clone_from_slice(plain.as_ref());
                                }
                            } else {
                                break
                            }
                        }
                    }
                } else {
                    let buffer = &*buffer;
                    if buffer.can_upgrade() {
                        identity
                            .map(|i| {
                                let initiator = &buffer.incoming.data()[buffer.incoming.chunks()[0].clone()];
                                let responder = &buffer.outgoing.data()[buffer.outgoing.chunks()[0].clone()];
                                *decipher = i.decipher_from_raw(initiator, responder);
                            });
                    }
                }
            }
            Context::Unrecognized => (),
        };
    }

    pub fn invalid(&self) -> bool {
        match self {
            &Context::Unrecognized => true,
            _ => false
        }
    }

    pub fn id(&self) -> String {
        format!("{:?}", self.buffer().addresses)
    }

    fn buffer(&self) -> &ConversationBuffer {
        match self {
            &Context::Empty => panic!(),
            &Context::Handshake(ref buffer, _) => buffer,
            &Context::Unrecognized => panic!(),
        }
    }

    pub fn visualize(&mut self, packet_length: usize, packet_info: &PacketInfo, root: &mut Tree) {
        let mut node = root.add("tezos", 0..packet_length, TreeLeaf::nothing()).subtree();
        node.add("conversation_id", 0..0, TreeLeaf::Display(self.id()));

        let _ = packet_length;
        let buffer = self.buffer();

        let direction = match buffer.addresses.sender(packet_info) {
            Sender::Initiator(()) => "from initiator",
            Sender::Responder(()) => "from responder",
        };
        node.add("direction", 0..0, TreeLeaf::Display(direction));

        let space = buffer.packet(packet_info);
        let chunks = buffer.chunks(packet_info)
            .iter()
            .enumerate()
            .map(|(index, range)| {
                if index == 0 {
                    (range.start + 2)..range.end
                } else {
                    (range.start + 2)..(range.end - 16)
                }
            })
            .collect::<Vec<_>>();
        let first_chunk = chunks.iter()
            .enumerate()
            .find(|&(_, ref range)| range.end > space.start)
            .map(|(i, _)| i);
        if let Some(first_chunk) = first_chunk {
            let mut chunks = &chunks[first_chunk..];
            let mut offset = chunks[0].start;
            let (encoding, base) = match first_chunk {
                0 => (ConnectionMessage::encoding(), ConnectionMessage::NAME),
                1 => (MetadataMessage::encoding(), MetadataMessage::NAME),
                _ => (PeerMessageResponse::encoding(), PeerMessageResponse::NAME),
            };
            // already decrypted something
            if buffer.decrypted(packet_info) > first_chunk && first_chunk < 2 {
                show(
                    buffer.data(packet_info),
                    &mut chunks,
                    &encoding,
                    space,
                    base,
                    &mut node,
                    &mut offset,
                );
            }
        }
    }
}

impl Default for Context {
    fn default() -> Self {
        Context::Empty
    }
}
