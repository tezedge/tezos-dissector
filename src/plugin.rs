// Copyright (c) SimpleStaking and Tezedge Contributors
// SPDX-License-Identifier: MIT

#[rustfmt::skip]
use wireshark_epan_adapter::{
    Plugin, NameDescriptor, FieldDescriptor,
    PrefFilenameDescriptor,
    DissectorDescriptor,
};
use tezos_messages::p2p::encoding::{
    ack::AckMessage, metadata::MetadataMessage, peer::PeerMessageResponse,
};
use super::{
    dissector::TezosDissector,
    value::{TezosEncoded, ConnectionMessage},
};

#[no_mangle]
static plugin_version: &str = concat!(env!("CARGO_PKG_VERSION"), "\0");

#[no_mangle]
static plugin_want_major: i32 = 3;

#[no_mangle]
static plugin_want_minor: i32 = 2;

#[no_mangle]
extern "C" fn plugin_register() {
    if cfg!(debug_assertions) {
        let file = env!("PWD")
            .parse::<std::path::PathBuf>()
            .unwrap()
            .join("target/log.txt");
        simple_logging::log_to_file(file, log::LevelFilter::Info).unwrap();
    }

    Plugin::new(
        DissectorDescriptor {
            display_name: "Tezos\0",
            short_name: "tezos_tcp\0",
        },
        NameDescriptor {
            name: "Tezos Protocol\0",
            short_name: "tezos\0",
            filter_name: "tezos\0",
        },
        &[
            &[
                FieldDescriptor::String {
                    name: "Conversation\0",
                    abbrev: "tezos.conversation_id\0",
                },
                FieldDescriptor::String {
                    name: "Direction\0",
                    abbrev: "tezos.direction\0",
                },
            ],
            // chunk
            &[
                FieldDescriptor::Int64Dec {
                    name: "Chunk\0",
                    abbrev: "tezos.chunk\0",
                },
                FieldDescriptor::Int64Dec {
                    name: "Chunk length\0",
                    abbrev: "tezos.chunk.length\0",
                },
                FieldDescriptor::String {
                    name: "Decrypted data\0",
                    abbrev: "tezos.chunk.decrypted_data\0",
                },
                FieldDescriptor::String {
                    name: "MAC mismatch\0",
                    abbrev: "tezos.chunk.mac_error\0",
                },
                FieldDescriptor::String {
                    name: "Identity required\0",
                    abbrev: "tezos.chunk.identity_required\0",
                },
                FieldDescriptor::String {
                    // only for first pass
                    name: "Buffering\0",
                    abbrev: "tezos.chunk.buffering\0",
                },
                FieldDescriptor::String {
                    name: "Message authentication code\0",
                    abbrev: "tezos.chunk.mac\0",
                },
            ],
        ],
        &[PrefFilenameDescriptor {
            name: "identity_json_file\0",
            title: "Identity JSON file\0",
            description: "JSON file with node identity information\0",
        }],
    )
    .register_type::<TezosEncoded<ConnectionMessage>>()
    .register_type::<TezosEncoded<AckMessage>>()
    .register_type::<TezosEncoded<MetadataMessage>>()
    .register_type::<TezosEncoded<PeerMessageResponse>>()
    .register(Box::new(TezosDissector::new()))
}
