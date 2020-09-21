// Copyright (c) SimpleStaking and Tezedge Contributors
// SPDX-License-Identifier: MIT

#![forbid(unsafe_code)]
#![allow(clippy::match_ref_pats, clippy::clone_on_copy, clippy::len_zero)]

mod plugin;

mod dissector;

mod conversation;

mod value;

mod range_tool;

mod identity;

pub mod proof_of_work;

// public interface for fuzz
pub use wireshark_epan_adapter::dissector::{PacketMetadata, SocketAddress, TreePresenter, TreeLeaf};
pub use crate::identity::{Identity, IdentityError, Decipher, NonceAddition};
pub use self::conversation::{Context, ErrorPosition, Sender};
