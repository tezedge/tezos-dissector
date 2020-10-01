// Copyright (c) SimpleStaking and Tezedge Contributors
// SPDX-License-Identifier: MIT

// the order matters,
// direct_buffer uses addresses and chunk_info
// overall_buffer uses addresses and direct_buffer
// conversation uses them all

/// Store source and destination of first message,
/// can determine who is initiator, and who responder
mod addresses;

/// Store chunk range, 'know' which chunks are the same message,
/// and 'know' that first chunk has no MAC
mod chunk_info;

/// buffer of incoming *or* outgoing packets, assemble chunks, store packet ranges
mod direct_buffer;

/// both incoming and outgoing buffer and also addresses
mod overall_buffer;

/// the whole conversation information, so called conversation context
// TODO: refactor, simplify
mod context;

mod context_wrapper;

pub use self::addresses::{ChunkMetadata, Sender};
pub use self::chunk_info::{ChunkInfo, ChunkInfoPair};
pub use self::overall_buffer::{ChunkPosition, ConsumeResult};
pub use self::context::ChunkInfoProvider;
pub use self::context_wrapper::Conversation;
