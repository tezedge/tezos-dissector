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
    direct_buffer::{DirectBuffer, DecryptError, ChunkInfo},
};
use crate::{
    identity::{Decipher, Identity},
    value::{ChunkedData, ChunkedDataOffset, Named, ConnectionMessage, HasBodyRange},
    range_tool::intersect,
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

impl State {
    fn error(&self, i: usize) -> bool {
        match self {
            &State::Correct => false,
            &State::HaveNoIdentity => true,
            &State::DecryptError(ref e) => i >= e.chunk_number,
        }
    }
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
                self.incoming.data().len() >= i.range().end
                    && self.outgoing.data().len() >= o.range().end
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

    fn chunks(&self, packet_info: &PacketInfo) -> &[ChunkInfo] {
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
                                &buffer.incoming.data()[buffer.incoming.chunks()[0].range()];
                            let responder =
                                &buffer.outgoing.data()[buffer.outgoing.chunks()[0].range()];
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

        let space = &buffer.packet(packet_info);
        let data = buffer.data(packet_info);
        let decrypted = buffer.decrypted(packet_info);
        let chunks = buffer.chunks(packet_info);

        chunks.iter().enumerate().for_each(|(index, chunk_info)| {
            let range = chunk_info.range();
            if range.end > space.start && range.start < space.end {
                if let &State::DecryptError(ref e) = state {
                    if state.error(index) {
                        node.add("decryption_error", 0..0, TreeLeaf::Display(e));
                        return;
                    }
                }
                if !state.error(index) {
                    let item = intersect(space, range.clone());
                    let mut chunk_node =
                        node.add("chunk", item, TreeLeaf::dec(index as _)).subtree();

                    let length = range.len() as i64 - 2;
                    let item = intersect(space, range.start..(range.start + 2));
                    chunk_node.add("length", item, TreeLeaf::dec(length));

                    let body_range = chunk_info.body();

                    if decrypted > index {
                        data[body_range.clone()]
                            .chunks(0x10)
                            .enumerate()
                            .for_each(|(i, line)| {
                                let start = body_range.start + i * 0x10;
                                let end = start + line.len();
                                let body_hex = line.iter().fold(String::new(), |s, b| {
                                    s + hex::encode(&[*b]).as_str() + " "
                                });
                                let item = intersect(space, start..end);
                                chunk_node.add("data", item, TreeLeaf::Display(body_hex));
                            })
                    } else {
                        let item = intersect(space, body_range.clone());
                        chunk_node.add("buffering", item, TreeLeaf::Display("..."));
                    }

                    if index > 0 && data.len() >= range.end {
                        let mac_range = body_range.end..range.end;
                        let mac = hex::encode(&data[mac_range.clone()]);
                        let item = intersect(space, mac_range.clone());
                        chunk_node.add("mac", item, TreeLeaf::Display(mac));
                    }
                }
            }
        });

        let chunks = &chunks[..decrypted];

        // first chunk which intersect with the frame
        // but it might be a continuation of previous message,
        let find_result = chunks
            .iter()
            .enumerate()
            .find(|&(_, info)| info.body().end > space.start)
            .map(|(i, info)| (i, info.continuation()));

        // find the chunk that is not a continuation
        let first_chunk = find_result.map(|(first_chunk, continuation)| {
            if continuation {
                // safe to subtract 1 because the first chunk cannot be a continuation
                chunks[0..(first_chunk - 1)]
                    .iter()
                    .enumerate()
                    .rev()
                    .find(|&(_, info)| !info.continuation())
                    .unwrap()
                    .0
            } else {
                first_chunk
            }
        });

        let data = ChunkedData::new(data, chunks);
        if let Some(first_chunk) = first_chunk {
            let mut offset = ChunkedDataOffset {
                chunks_offset: first_chunk,
                data_offset: chunks[first_chunk].body().start,
            };
            loop {
                let on = chunks
                    .get(offset.chunks_offset)
                    .map(|c| c.body().start < space.end)
                    .unwrap_or(false);
                if !on {
                    break;
                }
                offset.data_offset = chunks[offset.chunks_offset].body().start;
                let (encoding, base) = match offset.chunks_offset {
                    0 => (ConnectionMessage::encoding(), ConnectionMessage::NAME),
                    1 => (MetadataMessage::encoding(), MetadataMessage::NAME),
                    2 => (AckMessage::encoding(), AckMessage::NAME),
                    _ => (PeerMessageResponse::encoding(), PeerMessageResponse::NAME),
                };
                let temp = offset.chunks_offset;
                match data.show(&mut offset, &encoding, space, base, &mut node) {
                    Ok(()) => (),
                    Err(e) => {
                        let leaf = TreeLeaf::Display(e);
                        node.add("decoding_error", 0..0, leaf);
                        break;
                    },
                }
                if offset.chunks_offset == temp {
                    offset.chunks_offset += 1;
                    //log::warn!(
                    //    "ChunkedData::show did not consume full chunk, frame: {}",
                    //    packet_info.frame_number()
                    //);
                }
                chunks[(temp + 1)..offset.chunks_offset]
                    .iter()
                    .for_each(ChunkInfo::set_continuation);
            }
        }
    }
}
