// Copyright (c) SimpleStaking and Tezedge Contributors
// SPDX-License-Identifier: MIT

use tezos_encoding::binary_reader::BinaryReaderError;
use tezos_messages::p2p::{
    encoding::version::NetworkVersion,
    binary_message::{
        BinaryChunk, BinaryMessage,
        cache::{CachedData, CacheReader, CacheWriter, BinaryDataCache},
    },
};
use serde::{Serialize, Deserialize};
use tezos_encoding::encoding::{Field, HasEncoding, Encoding};
use std::{io::Cursor, convert::TryFrom};

#[derive(Serialize, Deserialize, Debug, Clone)]
/// Mapped connection message as defined in tezos protocol
pub struct ConnectionMessage {
    pub port: u16,
    pub versions: Vec<NetworkVersion>,
    pub public_key: Vec<u8>,
    pub proof_of_work_stamp: Vec<u8>,
    pub message_nonce: Vec<u8>,

    #[serde(skip_serializing)]
    body: BinaryDataCache,
}

impl TryFrom<BinaryChunk> for ConnectionMessage {
    type Error = BinaryReaderError;

    fn try_from(value: BinaryChunk) -> Result<Self, Self::Error> {
        let cursor = Cursor::new(value.content());
        ConnectionMessage::from_bytes(cursor.into_inner().to_vec())
    }
}

impl HasEncoding for ConnectionMessage {
    fn encoding() -> Encoding {
        Encoding::Obj(vec![
            Field::new("port", Encoding::Uint16),
            Field::new("public_key", Encoding::sized(32, Encoding::Bytes)),
            Field::new("proof_of_work_stamp", Encoding::sized(24, Encoding::Bytes)),
            Field::new("message_nonce", Encoding::sized(24, Encoding::Bytes)),
            //Field::new("versions", Encoding::list(NetworkVersion::encoding())),
            // WARNING: fix it
            Field::new("versions", NetworkVersion::encoding()),
        ])
    }
}

impl CachedData for ConnectionMessage {
    #[inline]
    fn cache_reader(&self) -> &dyn CacheReader {
        &self.body
    }

    #[inline]
    fn cache_writer(&mut self) -> Option<&mut dyn CacheWriter> {
        Some(&mut self.body)
    }
}
