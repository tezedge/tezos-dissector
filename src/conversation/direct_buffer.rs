// Copyright (c) SimpleStaking and Tezedge Contributors
// SPDX-License-Identifier: MIT

use std::{ops::Range, collections::BTreeMap};
use bytes::Buf;
use super::addresses::Sender;
use crate::identity::{Decipher, NonceAddition};

pub struct DirectBuffer {
    data: Vec<u8>,
    chunks: Vec<Range<usize>>,
    packets: BTreeMap<u64, Range<usize>>,
    decrypted: usize,
}

impl DirectBuffer {
    pub fn new() -> Self {
        DirectBuffer {
            data: Vec::with_capacity(0x100000),
            chunks: Vec::with_capacity(0x1000),
            packets: BTreeMap::new(),
            // first message always decrypted
            decrypted: 1,
        }
    }

    pub fn consume(&mut self, payload: &[u8], frame_index: u64) {
        let start = self.data.len();
        self.data.extend_from_slice(payload);
        let end = self.data.len();
        self.packets.insert(frame_index, start..end);
        let mut position = self.chunks.last().map(|r| r.end).unwrap_or(0);

        loop {
            if position + 2 < end {
                let length = (&self.data[position..(position + 2)]).get_u16() as usize;
                let this_end = position + 2 + length;
                self.chunks.push(position..this_end);
                position = this_end;
            } else {
                break;
            }
        }
    }

    pub fn decrypt(&mut self, decipher: &Decipher, sender: Sender) -> Result<(), ()> {
        if self.chunks().len() > self.decrypted {
            let chunks = (&self.chunks()[self.decrypted..]).to_vec();
            for chunk in chunks {
                if self.data().len() >= chunk.end {
                    let nonce = match sender {
                        Sender::Initiator => NonceAddition::Initiator((self.decrypted - 1) as u64),
                        Sender::Responder => NonceAddition::Responder((self.decrypted - 1) as u64),
                    };
                    let data = &self.data()[(chunk.start + 2)..chunk.end];
                    if let Ok(plain) = decipher.decrypt(data, nonce) {
                        self.decrypted += 1;
                        self.data_mut()[(chunk.start + 2)..(chunk.end - 16)]
                            .clone_from_slice(plain.as_ref());
                    } else {
                        return Err(());
                    }
                } else {
                    break;
                }
            }
        }
        Ok(())
    }

    pub fn decrypted(&self) -> usize {
        self.decrypted
    }

    pub fn data(&self) -> &[u8] {
        self.data.as_ref()
    }

    pub fn data_mut(&mut self) -> &mut [u8] {
        self.data.as_mut()
    }

    pub fn chunks(&self) -> &[Range<usize>] {
        self.chunks.as_ref()
    }

    pub fn packet(&self, index: u64) -> Range<usize> {
        self.packets.get(&index).unwrap().clone()
    }
}
