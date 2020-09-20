// Copyright (c) SimpleStaking and Tezedge Contributors
// SPDX-License-Identifier: MIT

use std::{ops::Range, cell::Cell};
use crate::value::HasBodyRange;

/// Store range of the chunk and information
/// either this is a start of a new message, or continuation of message
#[derive(Clone)]
pub struct ChunkInfo {
    inner: Cell<Inner>,
}

#[derive(Copy, Clone)]
struct Inner {
    start: usize,
    end: usize,
    // false means this chunk start a new message,
    // true means this chunk is a continuation of some message,
    continuation: bool,
}

impl ChunkInfo {
    pub fn new(start: usize, end: usize) -> Self {
        ChunkInfo {
            inner: Cell::new(Inner {
                start,
                end,
                continuation: false,
            }),
        }
    }

    pub fn range(&self) -> Range<usize> {
        let inner = self.inner.get();
        inner.start..inner.end
    }

    pub fn set_continuation(&self) {
        let inner = self.inner.get();
        self.inner.set(Inner {
            start: inner.start,
            end: inner.end,
            continuation: true,
        });
    }

    pub fn continuation(&self) -> bool {
        self.inner.get().continuation
    }
}

impl HasBodyRange for ChunkInfo {
    fn body(&self) -> Range<usize> {
        let range = self.range();
        if range.start == 0 {
            // first chunk is plain, has no MAC
            (range.start + 2)..range.end
        } else {
            (range.start + 2)..(range.end - 16)
        }
    }
}
