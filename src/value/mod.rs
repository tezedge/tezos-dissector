// Copyright (c) SimpleStaking and Tezedge Contributors
// SPDX-License-Identifier: MIT

mod buffer;
mod fields;
mod message;
mod named;

use std::ops::Range;

pub trait HasBodyRange {
    fn body(&self) -> Range<usize>;
    fn set_continuation(&self);
}

pub use self::fields::{TezosEncoded, Named};
pub use self::buffer::ChunkedDataBuffer;
pub use self::message::{DecodingError, show};
