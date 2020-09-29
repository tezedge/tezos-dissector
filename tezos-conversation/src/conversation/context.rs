// Copyright (c) SimpleStaking and Tezedge Contributors
// SPDX-License-Identifier: MIT

use wireshark_definitions::{NetworkPacket, TreePresenter, TreeLeaf};
use tezos_encoding::encoding::HasEncoding;
use tezos_messages::p2p::encoding::{
    ack::AckMessage, metadata::MetadataMessage, peer::PeerMessageResponse,
    connection::ConnectionMessage,
};
use failure::Fail;
use std::ops::Range;
use super::{addresses::Sender, direct_buffer::ChunkPosition, overall_buffer::ConversationBuffer};
use crate::{
    identity::{Decipher, Identity, IdentityError},
    value::{ChunkedData, Named, HasBodyRange, show},
    range_tool::intersect,
};

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
    Unrecognized,
}

impl ContextInner {
    pub fn new(packet: &NetworkPacket, pow_target: f64) -> Self {
        let b = ConversationBuffer::new(packet, pow_target);
        ContextInner::Regular(b, None, State::Correct)
    }

    pub fn consume(
        &mut self,
        packet: &NetworkPacket,
        identity: Option<&(Identity, String)>,
    ) -> Option<Range<usize>> {
        match self {
            &mut ContextInner::Regular(ref mut buffer, ref mut decipher, ref mut state) => {
                let (space, result) = buffer.consume(packet);
                match result {
                    Ok(()) => (),
                    Err(()) => {
                        *self = ContextInner::Unrecognized;
                        return Some(space);
                    },
                }
                if decipher.is_none() {
                    let buffer = &*buffer;
                    let sender = buffer.sender(packet);
                    if let Some((initiator, responder)) = buffer.can_upgrade() {
                        match identity {
                            Some(&(ref i, ref filename)) => {
                                *decipher = match i.decipher(initiator, responder) {
                                    Ok(decipher) => Some(decipher),
                                    Err(IdentityError::Invalid) => {
                                        *state = State::IdentityInvalid(filename.clone());
                                        None
                                    },
                                    Err(IdentityError::CannotDecrypt) => {
                                        *state = State::IdentityCannotDecrypt(filename.clone());
                                        None
                                    },
                                }
                            },
                            None => {
                                *state = State::HaveNoIdentity;
                            },
                        }
                    } else if buffer.direct_buffer(&sender).chunks().len() > 1 {
                        *self = ContextInner::Unrecognized;
                        return Some(space);
                    }
                }
                if let &mut Some(ref decipher) = decipher {
                    if let Err(e) = buffer.decrypt(decipher) {
                        log::warn!("cannot decrypt {}", e);
                        match e.chunk_number {
                            0 => panic!("impossible, the first message is never encrypted"),
                            // if cannot decrypt the first message,
                            // most likely it is not our conversation
                            1 => *self = ContextInner::Unrecognized,
                            _ => *state = State::DecryptError(e),
                        }
                    }
                }
                Some(space)
            },
            &mut ContextInner::Unrecognized => None,
        }
    }

    pub fn invalid(&self) -> bool {
        match self {
            &ContextInner::Unrecognized => true,
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
            &ContextInner::Unrecognized => panic!("call `Context::visualize` on invalid context"),
        }
    }

    fn state(&self) -> &State {
        match self {
            &ContextInner::Regular(_, _, ref state, ..) => state,
            &ContextInner::Unrecognized => panic!("call `Context::visualize` on invalid context"),
        }
    }

    pub fn after(&self, packet: &NetworkPacket, error_position: &ErrorPosition) -> bool {
        if self.buffer().sender(packet) == error_position.sender {
            packet.number > error_position.frame_number
        } else {
            false
        }
    }

    /// Returns if there is decryption error.
    pub fn visualize<T>(&self, packet: &NetworkPacket, offset: usize, root: &mut T) -> Result<(), ErrorPosition>
    where
        T: TreePresenter,
    {
        let sender = self.buffer().sender(packet);
        let buffer = self.buffer().direct_buffer(&sender);
        let space = offset..(offset + packet.payload.len());
        let data = buffer.data();
        let decrypted = buffer.decrypted();
        let chunks = buffer.chunks();
        let state = self.state();

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

        // TODO: split it in separated methods
        for (index, chunk_info) in chunks.iter().enumerate() {
            let range = chunk_info.range();
            let chunk_position = ChunkPosition {
                sender: sender.clone(),
                chunk_number: index,
            };
            if range.end > space.start && range.start < space.end {
                if state.error(&chunk_position) {
                    node.add("decryption_error", 0..0, TreeLeaf::Display(state));
                    return Err(ErrorPosition {
                        sender,
                        frame_number: packet.number,
                    });
                } else {
                    let item = intersect(&space, range.clone());
                    let mut chunk_node =
                        node.add("chunk", item, TreeLeaf::dec(index as _)).subtree();

                    let length = range.len() as i64 - 2;
                    let item = intersect(&space, range.start..(range.start + 2));
                    chunk_node.add("length", item, TreeLeaf::dec(length));

                    if data.len() >= range.end {
                        let body_range = chunk_info.body();

                        if decrypted > index {
                            data[body_range.clone()].chunks(0x10).enumerate().for_each(
                                |(i, line)| {
                                    let start = body_range.start + i * 0x10;
                                    let end = start + line.len();
                                    let body_hex = line.iter().fold(String::new(), |s, b| {
                                        s + hex::encode(&[*b]).as_str() + " "
                                    });
                                    let item = intersect(&space, start..end);
                                    chunk_node.add("data", item, TreeLeaf::Display(body_hex));
                                },
                            )
                        } else {
                            let item = intersect(&space, body_range.clone());
                            chunk_node.add("buffering", item, TreeLeaf::Display("..."));
                        }

                        if index > 0 {
                            let mac_range = body_range.end..range.end;
                            let mac = hex::encode(&data[mac_range.clone()]);
                            let item = intersect(&space, mac_range);
                            chunk_node.add("mac", item, TreeLeaf::Display(mac));
                        }
                    }
                }
            }
        }

        let chunks = &chunks[..decrypted];

        // first chunk which intersect with the frame
        // but it might be a continuation of previous message,
        // seek back to find the chunk that is not a continuation
        let first_chunk = chunks
            .iter()
            .enumerate()
            .find(|&(_, info)| info.body().end > space.start)
            .map(|(i, info)| (i, info.continuation()))
            .map(|(first_chunk, continuation)| {
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

        if let Some(first_chunk) = first_chunk {
            if data.len() >= chunks.last().unwrap().body().end {
                let mut chunked_buffer = match ChunkedData::new(data, chunks, first_chunk) {
                    Some(chunked_buffer) => chunked_buffer,
                    None => return Ok(()),
                };
                let mut messages = messages;
                loop {
                    let chunk_position = ChunkPosition {
                        sender: sender.clone(),
                        chunk_number: chunked_buffer.chunk(),
                    };
                    if state.error(&chunk_position) {
                        chunked_buffer.skip();
                        continue;
                    }
                    if !chunked_buffer.on(&space) {
                        break;
                    }
                    let (encoding, base) = match chunked_buffer.chunk() {
                        0 => (ConnectionMessage::encoding(), ConnectionMessage::NAME),
                        1 => (MetadataMessage::encoding(), MetadataMessage::NAME),
                        2 => (AckMessage::encoding(), AckMessage::NAME),
                        _ => (PeerMessageResponse::encoding(), PeerMessageResponse::NAME),
                    };
                    let temp = chunked_buffer.chunk();
                    // if it is first chunk limit the buffer by just this one chunk,
                    // because connection message goes in single chunk
                    if temp == 0 {
                        chunked_buffer
                            .inner_mut()
                            .push_limit(chunks[0].body().len());
                    }
                    match show(&mut chunked_buffer, &space, &encoding, base, &mut messages) {
                        Ok(_) => {
                            if temp == 0 {
                                chunked_buffer.inner_mut().pop_limit();
                            }
                        },
                        Err(e) => {
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
            }
        }

        Ok(())
    }
}
