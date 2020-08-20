// Copyright (c) SimpleStaking and Tezedge Contributors
// SPDX-License-Identifier: MIT

use tezos_encoding::binary_reader::BinaryReaderError;
use tezos_messages::p2p::{
    encoding::version::NetworkVersion as Version,
    binary_message::{
        BinaryChunk, BinaryMessage,
        cache::{CachedData, CacheReader, CacheWriter, BinaryDataCache},
    },
};
use serde::{Serialize, Deserialize};
use tezos_encoding::encoding::{Field, HasEncoding, Encoding};
use wireshark_epan_adapter::{
    FieldDescriptor, FieldDescriptorOwned,
    dissector::{Tree, TreeMessage, HasFields, TreeMessageMapItem},
};
use std::{io::Cursor, convert::TryFrom};

#[derive(Serialize, Deserialize, Debug, Clone)]
/// Mapped connection message as defined in tezos protocol
pub struct ConnectionMessage {
    pub port: u16,
    pub versions: Vec<Version>,
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
            Field::new("versions", Encoding::list(Version::encoding())),
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

impl HasFields for ConnectionMessage {
    const FIELDS: &'static [FieldDescriptor<'static>] = &[
        FieldDescriptor::Nothing {
            name: "Connection message\0",
            abbrev: "tezos.connection_msg\0",
        },
        FieldDescriptor::Int64Dec {
            name: "Port\0",
            abbrev: "tezos.connection_msg.port\0",
        },
        FieldDescriptor::String {
            name: "Public key\0",
            abbrev: "tezos.connection_msg.pk\0",
        },
        FieldDescriptor::String {
            name: "Proof of work\0",
            abbrev: "tezos.connection_msg.pow\0",
        },
        FieldDescriptor::String {
            name: "Nonce\0",
            abbrev: "tezos.connection_msg.nonce\0",
        },
        FieldDescriptor::String {
            name: "Version\0",
            abbrev: "tezos.connection_msg.version\0",
        },
    ];

    fn fields() -> Vec<FieldDescriptorOwned> {
        vec![]
    }
}

impl TreeMessage for ConnectionMessage {
    fn show_on_tree(&self, node: &mut Tree, map: &[TreeMessageMapItem]) {
        use wireshark_epan_adapter::dissector::TreeLeaf;

        let _ = map;
        let mut n = node.add("connection_msg", 0..0, TreeLeaf::nothing()).subtree();
        n.add("port", 0..0, TreeLeaf::dec(self.port as _));
        n.add("pk", 0..0, TreeLeaf::Display(hex::encode(&self.public_key)));
        n.add("pow", 0..0, TreeLeaf::Display(hex::encode(&self.proof_of_work_stamp)));
        n.add("nonce", 0..0, TreeLeaf::Display(hex::encode(&self.message_nonce)));
        n.add("version", 0..0, TreeLeaf::Display(format!("{:?}", self.versions)));
    }
}
