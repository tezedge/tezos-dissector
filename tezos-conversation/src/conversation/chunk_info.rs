// Copyright (c) SimpleStaking and Tezedge Contributors
// SPDX-License-Identifier: MIT

use std::{ops::Range, cell::Cell};
use crate::value::HasBodyRange;

/// Store range of the chunk and information
/// either this is a start of a new message, or continuation of message
#[derive(Clone)]
pub struct ChunkInfo {
    range: Range<usize>,
    data: Vec<u8>,
    // false means this chunk start a new message,
    // true means this chunk is a continuation of some message,
    continuation: Cell<bool>,
    incomplete: Cell<bool>,
}

pub struct ChunkInfoPair {
    pub encrypted: ChunkInfo,
    pub decrypted: ChunkInfo,
}

impl ChunkInfo {
    pub fn new(range: Range<usize>, data: Vec<u8>) -> Self {
        ChunkInfo {
            range,
            data,
            continuation: Cell::new(false),
            incomplete: Cell::new(false),
        }
    }

    pub fn range(&self) -> Range<usize> {
        self.range.clone()
    }

    pub fn continuation(&self) -> bool {
        self.continuation.get()
    }

    pub fn incomplete(&self) -> bool {
        self.incomplete.get()
    }

    pub fn decrypt<Decipher>(self, mut decipher: Decipher) -> Result<ChunkInfoPair, Self>
    where
        Decipher: FnMut(&[u8]) -> Option<Vec<u8>>,
    {
        let mut s = self.clone();
        let l = s.data.len();
        if let Some(plain) = decipher(&s.data[2..]) {
            s.data[2..(l - 16)].clone_from_slice(plain.as_ref());
            Ok(ChunkInfoPair {
                encrypted: self,
                decrypted: s,
            })
        } else {
            Err(self)
        }
    }
}

impl HasBodyRange for ChunkInfo {
    fn data(&self) -> &[u8] {
        self.data.as_ref()
    }

    fn body(&self) -> Range<usize> {
        let range = self.range();
        if range.start == 0 {
            // first chunk is plain, has no MAC
            (range.start + 2)..range.end
        } else {
            (range.start + 2)..(range.end - 16)
        }
    }

    fn set_continuation(&self) {
        self.continuation.set(true);
    }

    fn set_incomplete(&self) {
        self.incomplete.set(true);
    }
}
