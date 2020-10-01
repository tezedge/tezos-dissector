// Copyright (c) SimpleStaking and Tezedge Contributors
// SPDX-License-Identifier: MIT

use wireshark_definitions::NetworkPacket;
use failure::Fail;
use std::ops::Range;
use super::{
    addresses::{Addresses, ChunkMetadata, Sender},
    chunk_info::{ChunkInfo, ChunkInfoPair},
    direct_buffer::DirectBuffer,
};
use crate::identity::{Decipher, NonceAddition};

#[derive(Debug, Fail, Eq, PartialEq)]
#[fail(
    display = "MAC mismatch, sender: {:?}, number of chunk: {}",
    sender, chunk_number
)]
pub struct ChunkPosition {
    pub sender: Sender,
    pub chunk_number: usize,
}

pub struct ConversationBuffer {
    addresses: Addresses,
    pow_target: f64,
    incoming: DirectBuffer,
    outgoing: DirectBuffer,
}

pub enum ConsumeResult {
    PowInvalid,
    Pending,
    ConnectionMessage(ChunkInfo),
    ExpectedConnectionMessage,
    Chunks {
        regular: Vec<ChunkInfoPair>,
        failed_to_decrypt: Vec<ChunkInfo>,
    },
    NoDecipher(Vec<ChunkInfo>),
}

impl ConversationBuffer {
    pub fn new(packet: &NetworkPacket, pow_target: f64) -> Self {
        ConversationBuffer {
            addresses: Addresses::new(packet),
            pow_target,
            incoming: DirectBuffer::new(),
            outgoing: DirectBuffer::new(),
        }
    }

    pub fn consume(
        &mut self,
        packet: &NetworkPacket,
        decipher: Option<&Decipher>,
    ) -> (ConsumeResult, Range<usize>, Option<ChunkPosition>) {
        let target = self.pow_target;
        let sender = self.sender(packet);
        let buffer = self.direct_buffer_mut(&sender);
        let (packet_range, chunks, pow_valid) = buffer.consume(packet.payload.as_ref(), target);
        if !pow_valid {
            return (ConsumeResult::PowInvalid, packet_range, None);
        }
        if chunks.is_empty() {
            return (ConsumeResult::Pending, packet_range, None);
        }
        if buffer.chunks_number() == chunks.len() {
            if chunks.len() == 1 {
                let message = chunks[0].clone();
                return (
                    ConsumeResult::ConnectionMessage(message),
                    packet_range,
                    None,
                );
            } else {
                return (ConsumeResult::ExpectedConnectionMessage, packet_range, None);
            }
        }
        if let Some(decipher) = decipher {
            let mut regular = Vec::with_capacity(chunks.len());
            let mut failed_to_decrypt = Vec::new();
            let i_base = buffer.chunks_number() - 1 - chunks.len();
            let mut error = None;
            for (i, chunk) in chunks.into_iter().enumerate() {
                let i = i_base + i;
                let nonce_addition = match &sender {
                    &Sender::Initiator => NonceAddition::Initiator(i as u64),
                    &Sender::Responder => NonceAddition::Responder(i as u64),
                };
                match chunk.decrypt(|data| decipher.decrypt(data, nonce_addition).ok()) {
                    Ok(decrypted) => regular.push(decrypted),
                    Err(failed) => {
                        if error.is_none() {
                            error = Some(ChunkPosition {
                                sender: sender.clone(),
                                chunk_number: i,
                            })
                        }
                        failed_to_decrypt.push(failed)
                    },
                }
            }
            (
                ConsumeResult::Chunks {
                    regular,
                    failed_to_decrypt,
                },
                packet_range,
                error,
            )
        } else {
            (ConsumeResult::NoDecipher(chunks), packet_range, None)
        }
    }

    pub fn id(&self) -> String {
        format!("{}", self.addresses)
    }

    pub fn can_upgrade(&self) -> Option<(&[u8], &[u8])> {
        let i = !self.incoming.connection_message().is_empty();
        let o = !self.outgoing.connection_message().is_empty();
        if i && o {
            Some((
                self.incoming.connection_message(),
                self.outgoing.connection_message(),
            ))
        } else {
            None
        }
    }

    pub fn direct_buffer(&self, sender: &Sender) -> &DirectBuffer {
        match sender {
            &Sender::Initiator => &self.incoming,
            &Sender::Responder => &self.outgoing,
        }
    }

    fn direct_buffer_mut(&mut self, sender: &Sender) -> &mut DirectBuffer {
        match sender {
            &Sender::Initiator => &mut self.incoming,
            &Sender::Responder => &mut self.outgoing,
        }
    }

    pub fn sender(&self, packet: &NetworkPacket) -> Sender {
        self.addresses.sender(packet)
    }

    pub fn metadata(&self, packet: &NetworkPacket) -> ChunkMetadata {
        self.addresses.metadata(packet)
    }
}
