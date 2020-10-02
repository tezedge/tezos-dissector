// Copyright (c) SimpleStaking and Tezedge Contributors
// SPDX-License-Identifier: MIT

#![forbid(unsafe_code)]
#![allow(
    clippy::match_ref_pats,
    clippy::clone_on_copy,
    clippy::len_zero,
    clippy::new_without_default
)]

mod conversation;

mod value;

mod range_tool;

mod identity;

pub mod proof_of_work;

mod simulator;

pub use self::identity::{Identity, IdentityError, Decipher, NonceAddition};
pub use self::conversation::{
    Conversation, ChunkMetadata, ChunkInfo, ChunkInfoPair, ChunkPosition, Sender, ConsumeResult,
    ChunkInfoProvider,
};
pub use self::value::{TezosEncoded, Named, HasBodyRange};
pub use self::simulator::{
    Tree, PacketDescriptor, ChunkDescriptor, simulate_foreign, simulate_handshake,
    simulate_encrypted,
};
