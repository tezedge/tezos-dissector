// Copyright (c) SimpleStaking and Tezedge Contributors
// SPDX-License-Identifier: MIT

use wireshark_definitions::{TreePresenter, TreeLeaf};
use tezos_encoding::encoding::HasEncoding;
use tezos_messages::p2p::encoding::{
    ack::AckMessage, metadata::MetadataMessage, peer::PeerMessageResponse,
    connection::ConnectionMessage,
};
use failure::Fail;
use std::ops::Range;
use super::{
    addresses::{Sender, Packet, Addresses},
    chunk_info::ChunkInfo,
    overall_buffer::{ConversationBuffer, ConsumeResult, ChunkPosition},
};
use crate::{
    identity::{Decipher, Identity, IdentityError},
    value::{ChunkedData, Named, ChunkMetadata, DecodingError, show},
    range_tool::intersect,
};

pub trait ChunkInfoProvider {
    fn packet_range(&self, packet_index: u64) -> Option<&Range<usize>>;
    fn chunks_after(&self, sender: &Sender, offset: usize) -> Option<(usize, &[ChunkInfo])>;
}

#[derive(Debug, Eq, PartialEq, Fail)]
pub enum State {
    #[fail(display = "Correct")]
    Correct,
    #[fail(display = "Have no identity")]
    HaveNoIdentity,
    #[fail(display = "Identity at: {} is invalid", _0)]
    IdentityInvalid(String),
    #[fail(display = "Identity at: {} cannot decrypt this conversation", _0)]
    IdentityCannotDecrypt(String),
    #[fail(display = "{}", _0)]
    DecryptError(ChunkPosition),
}

impl State {
    fn error(&self, chunk_position: &ChunkPosition) -> bool {
        match self {
            &State::Correct => false,
            &State::HaveNoIdentity
            | &State::IdentityInvalid(_)
            | &State::IdentityCannotDecrypt(_) => true,
            &State::DecryptError(ref e) => chunk_position.eq(e),
        }
    }
}

pub struct ErrorPosition {
    pub sender: Sender,
    frame_number: u64,
}

pub enum ContextInner {
    Regular(ConversationBuffer, Option<Decipher>, State),
    Unrecognized(Addresses),
}

impl ContextInner {
    pub fn new(packet: &Packet, pow_target: f64) -> Self {
        let b = ConversationBuffer::new(packet, pow_target);
        ContextInner::Regular(b, None, State::Correct)
    }

    pub fn consume(
        &mut self,
        packet: &Packet,
        identity: Option<&Identity>,
    ) -> (ConsumeResult, Sender, Range<usize>) {
        match self {
            &mut ContextInner::Regular(ref mut buffer, ref mut decipher, ref mut state) => {
                let (consume_result, packet_range, error) =
                    buffer.consume(packet, decipher.as_mut());
                let buffer = &*buffer;
                let sender = buffer.sender(packet);

                if let &ConsumeResult::PowInvalid = &consume_result {
                    *self = ContextInner::Unrecognized(buffer.addresses());
                    return (consume_result, sender, packet_range);
                }
                if decipher.is_none() {
                    if let Some((initiator, responder)) = buffer.can_upgrade() {
                        match identity {
                            Some(i) => {
                                *decipher = match i.decipher(initiator, responder) {
                                    Ok(decipher) => Some(decipher),
                                    Err(IdentityError::Invalid) => {
                                        *state = State::IdentityInvalid(i.path());
                                        None
                                    },
                                    Err(IdentityError::CannotDecrypt) => {
                                        *state = State::IdentityCannotDecrypt(i.path());
                                        None
                                    },
                                }
                            },
                            None => {
                                *state = State::HaveNoIdentity;
                            },
                        }
                    } else if buffer.direct_buffer(&sender).chunks_number() > 1 {
                        *self = ContextInner::Unrecognized(buffer.addresses());
                        return (consume_result, sender, packet_range);
                    }
                }
                if let Some(error) = error {
                    if let &State::DecryptError(_) = &*state {
                        // already reported
                    } else {
                        log::warn!("cannot decrypt {}", error);
                    }
                    *state = State::DecryptError(error);
                }
                (consume_result, sender, packet_range)
            },
            &mut ContextInner::Unrecognized(ref addresses) => 
                (ConsumeResult::InvalidConversation, addresses.sender(packet), 0..0),
        }
    }

    pub fn invalid(&self) -> bool {
        match self {
            &ContextInner::Unrecognized(_) => true,
            _ => false,
        }
    }

    pub fn id(&self) -> Option<String> {
        if self.invalid() {
            None
        } else {
            Some(self.buffer().id())
        }
    }

    fn buffer(&self) -> &ConversationBuffer {
        match self {
            &ContextInner::Regular(ref buffer, ..) => buffer,
            &ContextInner::Unrecognized(_) => panic!("call `Context::visualize` on invalid context"),
        }
    }

    fn state(&self) -> &State {
        match self {
            &ContextInner::Regular(_, _, ref state, ..) => state,
            &ContextInner::Unrecognized(_) => panic!("call `Context::visualize` on invalid context"),
        }
    }

    pub fn after(&self, packet: &Packet, error_position: &ErrorPosition) -> bool {
        if self.buffer().sender(packet) == error_position.sender {
            packet.number > error_position.frame_number
        } else {
            false
        }
    }

    /// Returns if there is decryption error.
    pub fn visualize<T, P>(
        &self,
        packet: &Packet,
        offset: usize,
        provider: &P,
        root: &mut T,
    ) -> Result<(), ErrorPosition>
    where
        T: TreePresenter,
        P: ChunkInfoProvider,
    {
        let sender = self.buffer().sender(packet);
        let space = offset..(offset + packet.payload.len());
        let state = self.state();

        let (first_chunk, chunks) = match provider.chunks_after(&sender, offset) {
            Some(x) => x,
            None => return Ok(()),
        };

        let mut node = root
            .add("tezos", 0..space.len(), TreeLeaf::nothing())
            .subtree();
        node.add(
            "conversation_id",
            0..0,
            TreeLeaf::Display(self.id().expect("valid context")),
        );

        let direction = match &sender {
            &Sender::Initiator => "local",
            &Sender::Responder => "remote",
        };
        node.add("source", 0..0, TreeLeaf::Display(direction));

        let messages = node.add("messages", 0..0, TreeLeaf::nothing()).subtree();

        for (index, chunk_info) in chunks.iter().enumerate() {
            let range = chunk_info.range();
            if range.start >= space.end && !chunk_info.incomplete() {
                break;
            }

            let chunk_position = ChunkPosition {
                sender: sender.clone(),
                chunk_number: first_chunk + index,
            };
            if state.error(&chunk_position) {
                node.add("decryption_error", 0..0, TreeLeaf::Display(state));
                return Err(ErrorPosition {
                    sender,
                    frame_number: packet.number,
                });
            } else {
                let item = intersect(&space, range.clone());
                let mut chunk_node =
                    node.add("chunk", item, TreeLeaf::dec((first_chunk + index) as _)).subtree();

                let length = range.len() as i64 - 2;
                let item = intersect(&space, range.start..(range.start + 2));
                chunk_node.add("length", item, TreeLeaf::dec(length));

                let body_range = chunk_info.body();
                let body_data = &chunk_info.data()[2..(range.len() - 16)];
                body_data.chunks(0x10).enumerate().for_each(
                    |(i, line)| {
                        let start = body_range.start + i * 0x10;
                        let end = start + line.len();
                        let body_hex = line.iter().fold(String::new(), |s, b| {
                            s + hex::encode(&[*b]).as_str() + " "
                        });
                        let item = intersect(&space, start..end);
                        chunk_node.add("data", item, TreeLeaf::Display(body_hex));
                    },
                );
                if first_chunk + index > 0 {
                    let mac_range = body_range.end..range.end;
                    let mac_data = &chunk_info.data()[(range.len() - 16)..];
                    let mac = hex::encode(mac_data);
                    let item = intersect(&space, mac_range);
                    chunk_node.add("mac", item, TreeLeaf::Display(mac));
                }
            }
        }

        let mut chunked_buffer = ChunkedData::new(chunks);
        let mut messages = messages;
        while chunked_buffer.on(&space) {
            let (encoding, base) = match first_chunk + chunked_buffer.chunk() {
                0 => (ConnectionMessage::encoding(), ConnectionMessage::NAME),
                1 => (MetadataMessage::encoding(), MetadataMessage::NAME),
                2 => (AckMessage::encoding(), AckMessage::NAME),
                _ => (PeerMessageResponse::encoding(), PeerMessageResponse::NAME),
            };
            let temp = chunked_buffer.chunk();
            // if it is first chunk limit the buffer by just this one chunk,
            // because connection message goes in single chunk
            if temp == 0 && first_chunk == 0 {
                chunked_buffer
                    .inner_mut()
                    .push_limit(chunks[0].body().len());
            }
            match show(&mut chunked_buffer, &space, &encoding, base, &mut messages) {
                Ok(_) => {
                    if temp == 0 && first_chunk == 0 {
                        chunked_buffer.inner_mut().pop_limit();
                    }
                },
                Err(e) => {
                    if let &DecodingError::NotEnoughData = &e {
                        chunks[chunked_buffer.chunk()].set_incomplete();
                    }
                    let leaf = TreeLeaf::Display(e);
                    node.add("decoding_error", 0..0, leaf);
                    break;
                },
            };
            chunked_buffer.complete_group(temp, || {
                log::warn!(
                    "ChunkedData::show did not consume full chunk, frame: {}",
                    packet.number,
                )
            });
        }

        Ok(())
    }
}
