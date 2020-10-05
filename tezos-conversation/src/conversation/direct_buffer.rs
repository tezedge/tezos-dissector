// Copyright (c) SimpleStaking and Tezedge Contributors
// SPDX-License-Identifier: MIT

use bytes::Buf;
use crypto::proof_of_work::check_proof_of_work;
use std::ops::Range;
use super::chunk_info::ChunkInfo;

pub struct DirectBuffer {
    offset: usize,
    buffer: Vec<u8>,
    chunks_number: usize,
    connection_message: Vec<u8>,
}

impl DirectBuffer {
    // 2 bytes chunk length + 2 bytes port = 4
    // 32 bytes public key + 24 bytes proof_of_work = 56
    const CHECK_RANGE: Range<usize> = 4..(4 + 56);

    pub fn new() -> Self {
        DirectBuffer {
            offset: 0,
            buffer: Vec::with_capacity(0x1000),
            chunks_number: 0,
            connection_message: Vec::new(),
        }
    }

    pub fn consume(&mut self, payload: &[u8], target: f64) -> (Range<usize>, Vec<ChunkInfo>, bool) {
        let checked = self.offset >= Self::CHECK_RANGE.end;

        let offset = self.offset;
        let end = offset + payload.len();
        self.offset = end;
        let mut position = offset - self.buffer.len();

        self.buffer.extend_from_slice(payload);

        let checking_result = if !checked && (end >= Self::CHECK_RANGE.end) {
            check_proof_of_work(&self.buffer[Self::CHECK_RANGE], target).is_ok()
        } else {
            true
        };

        let mut chunks = Vec::new();
        loop {
            if position + 2 <= end {
                let length = (&self.buffer[0..2]).get_u16() as usize;
                let this_end = position + 2 + length;
                if this_end <= end {
                    let chunk_data = self.buffer.drain(0..(length + 2)).collect::<Vec<_>>();
                    if chunks.is_empty() {
                        self.connection_message = chunk_data.clone();
                    }
                    chunks.push(ChunkInfo::new(position..this_end, chunk_data));
                    self.chunks_number += 1;
                    position = this_end;
                } else {
                    break (offset..end, chunks, checking_result);
                }
            } else {
                break (offset..end, chunks, checking_result);
            }
        }
    }

    pub fn chunks_number(&self) -> usize {
        self.chunks_number
    }

    pub fn connection_message(&self) -> &[u8] {
        self.connection_message.as_ref()
    }
}
