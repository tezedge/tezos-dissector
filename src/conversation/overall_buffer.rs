// Copyright (c) SimpleStaking and Tezedge Contributors
// SPDX-License-Identifier: MIT

use wireshark_epan_adapter::dissector::{PacketInfo, Tree, TreeLeaf};
use std::ops::Range;
use tezos_encoding::encoding::HasEncoding;
use tezos_messages::p2p::encoding::{
    ack::AckMessage, metadata::MetadataMessage, peer::PeerMessageResponse,
};
use failure::Fail;
use super::{
    addresses::{Addresses, Sender},
    direct_buffer::{DirectBuffer, DecryptError},
};
use crate::{
    identity::{Decipher, Identity},
    value::{ChunkedData, ChunkedDataOffset, Named, ConnectionMessage},
};

#[derive(Debug, Eq, PartialEq, Fail)]
pub enum State {
    #[fail(display = "Correct")]
    Correct,
    #[fail(display = "Have no identity")]
    HaveNoIdentity,
    #[fail(display = "{}", _0)]
    DecryptError(DecryptError),
}

pub enum Context {
    Regular(ConversationBuffer, Option<Decipher>, State),
    Unrecognized,
}

pub struct ConversationBuffer {
    addresses: Addresses,
    incoming: DirectBuffer,
    outgoing: DirectBuffer,
}

impl ConversationBuffer {
    fn consume(&mut self, payload: &[u8], packet_info: &PacketInfo) {
        match self.addresses.sender(packet_info) {
            Sender::Initiator => self.incoming.consume(payload, packet_info.frame_number()),
            Sender::Responder => self.outgoing.consume(payload, packet_info.frame_number()),
        }
    }

    fn can_upgrade(&self) -> bool {
        match (
            self.incoming.chunks().first(),
            self.outgoing.chunks().first(),
        ) {
            (Some(i), Some(o)) => {
                self.incoming.data().len() >= i.end && self.outgoing.data().len() >= o.end
            },
            _ => false,
        }
    }

    fn data(&self, packet_info: &PacketInfo) -> &[u8] {
        match self.addresses.sender(packet_info) {
            Sender::Initiator => self.incoming.data(),
            Sender::Responder => self.outgoing.data(),
        }
    }

    fn chunks(&self, packet_info: &PacketInfo) -> &[Range<usize>] {
        match self.addresses.sender(packet_info) {
            Sender::Initiator => self.incoming.chunks(),
            Sender::Responder => self.outgoing.chunks(),
        }
    }

    fn packet(&self, packet_info: &PacketInfo) -> Range<usize> {
        match self.addresses.sender(packet_info) {
            Sender::Initiator => self.incoming.packet(packet_info.frame_number()),
            Sender::Responder => self.outgoing.packet(packet_info.frame_number()),
        }
    }

    fn decrypt(&mut self, decipher: &Decipher) -> Result<(), DecryptError> {
        self.incoming.decrypt(decipher, Sender::Initiator)?;
        self.outgoing.decrypt(decipher, Sender::Responder)?;
        Ok(())
    }

    fn decrypted(&self, packet_info: &PacketInfo) -> usize {
        match self.addresses.sender(packet_info) {
            Sender::Initiator => self.incoming.decrypted(),
            Sender::Responder => self.outgoing.decrypted(),
        }
    }
}

impl Context {
    pub fn new(packet_info: &PacketInfo) -> Self {
        Context::Regular(
            ConversationBuffer {
                addresses: Addresses::new(packet_info),
                incoming: DirectBuffer::new(),
                outgoing: DirectBuffer::new(),
            },
            None,
            State::Correct,
        )
    }

    pub fn consume(
        &mut self,
        payload: &[u8],
        packet_info: &PacketInfo,
        identity: Option<&Identity>,
    ) {
        match self {
            &mut Context::Regular(ref mut buffer, ref mut decipher, ref mut state) => {
                buffer.consume(payload, packet_info);
                if decipher.is_none() {
                    let buffer = &*buffer;
                    if buffer.can_upgrade() {
                        identity.map(|i| {
                            let initiator =
                                &buffer.incoming.data()[buffer.incoming.chunks()[0].clone()];
                            let responder =
                                &buffer.outgoing.data()[buffer.outgoing.chunks()[0].clone()];
                            let d = i.decipher(initiator, responder);
                            if d.is_none() {
                                *state = State::HaveNoIdentity;
                            } else {
                                *state = State::Correct;
                            }
                            *decipher = d;
                        });
                    }
                }
                if let &mut Some(ref decipher) = decipher {
                    if let Err(e) = buffer.decrypt(decipher) {
                        log::warn!("cannot decrypt {}", e);
                        match e.chunk_number {
                            0 => panic!("impossible, the first message is never encrypted"),
                            // if cannot decrypt the first message,
                            // most likely it is not our conversation
                            1 => *self = Context::Unrecognized,
                            _ => *state = State::DecryptError(e),
                        }
                    }
                }
            },
            &mut Context::Unrecognized => (),
        };
    }

    pub fn invalid(&self) -> bool {
        match self {
            &Context::Unrecognized => true,
            _ => false,
        }
    }

    pub fn id(&self) -> String {
        format!("{:?}", self.buffer().addresses)
    }

    fn buffer(&self) -> &ConversationBuffer {
        match self {
            &Context::Regular(ref buffer, ..) => buffer,
            &Context::Unrecognized => panic!(),
        }
    }

    fn state(&self) -> &State {
        match self {
            &Context::Regular(_, _, ref state, ..) => state,
            &Context::Unrecognized => panic!(),
        }
    }

    pub fn visualize(&self, packet_length: usize, packet_info: &PacketInfo, root: &mut Tree) {
        let mut node = root
            .add("tezos", 0..packet_length, TreeLeaf::nothing())
            .subtree();
        node.add("conversation_id", 0..0, TreeLeaf::Display(self.id()));

        let state = self.state();
        let buffer = self.buffer();

        let direction = match buffer.addresses.sender(packet_info) {
            Sender::Initiator => "from initiator",
            Sender::Responder => "from responder",
        };
        node.add("direction", 0..0, TreeLeaf::Display(direction));

        let space = buffer.packet(packet_info);
        let chunks = buffer
            .chunks(packet_info)
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
        let data = ChunkedData::new(buffer.data(packet_info), chunks.as_ref());
        let space = &space;
        for (index, range) in chunks.iter().enumerate() {
            let intersect = range.end > space.start && range.start < space.end;
            if intersect && buffer.decrypted(packet_info) > index {
                let mut offset = ChunkedDataOffset {
                    chunks_offset: index,
                    data_offset: chunks[index].start,
                };
                let (encoding, base) = match index {
                    0 => (ConnectionMessage::encoding(), ConnectionMessage::NAME),
                    1 => (MetadataMessage::encoding(), MetadataMessage::NAME),
                    2 => (AckMessage::encoding(), AckMessage::NAME),
                    _ => (PeerMessageResponse::encoding(), PeerMessageResponse::NAME),
                };
                if let &State::DecryptError(ref e) = state {
                    if index >= e.chunk_number {
                        node.add("decryption_error", space.clone(), TreeLeaf::Display(e));
                        continue
                    }
                }
                if buffer.decrypted(packet_info) >= index {
                    data.show(&mut offset, &encoding, space, base, &mut node)
                        .unwrap_or_else(|()| {
                            // TODO:
                            // node.add("decoding_error", space.clone(), TreeLeaf::Display(e));
                            ()
                        })
                }
            }
        }
    }
}
