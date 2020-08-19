use super::dissector::TezosDissector;

#[rustfmt::skip]
use wireshark_epan_adapter::{
    Plugin, NameDescriptor, FieldDescriptor,
    PrefFilenameDescriptor,
    DissectorDescriptor,
};

#[no_mangle]
static plugin_version: &str = concat!(env!("CARGO_PKG_VERSION"), "\0");

#[no_mangle]
static plugin_want_major: i32 = 3;

#[no_mangle]
static plugin_want_minor: i32 = 2;

#[no_mangle]
extern "C" fn plugin_register() {
    let file = env!("PWD")
        .parse::<std::path::PathBuf>()
        .unwrap()
        .join("target/log.txt");
    simple_logging::log_to_file(file, log::LevelFilter::Info).unwrap();

    Plugin::new(NameDescriptor {
        name: "Tezos Protocol\0",
        short_name: "tezos\0",
        filter_name: "tezos\0",
    })
    .add_field(FieldDescriptor::Int64Dec {
        name: "Chunk length\0",
        abbrev: "tezos.chunk_length\0",
    })
    .add_field(FieldDescriptor::String {
        name: "Buffering incomplete chunk\0",
        abbrev: "tezos.buffering\0",
    })
    .add_field(FieldDescriptor::String {
        name: "Conversation\0",
        abbrev: "tezos.conversation_id\0",
    })
    .add_field(FieldDescriptor::String {
        name: "Connection message\0",
        abbrev: "tezos.connection_msg\0",
    })
    .add_field(FieldDescriptor::Int64Dec {
        name: "Port\0",
        abbrev: "tezos.connection_msg.port\0",
    })
    .add_field(FieldDescriptor::String {
        name: "Public key\0",
        abbrev: "tezos.connection_msg.pk\0",
    })
    .add_field(FieldDescriptor::String {
        name: "Proof of work\0",
        abbrev: "tezos.connection_msg.pow\0",
    })
    .add_field(FieldDescriptor::String {
        name: "Nonce\0",
        abbrev: "tezos.connection_msg.nonce\0",
    })
    .add_field(FieldDescriptor::String {
        name: "Version\0",
        abbrev: "tezos.connection_msg.version\0",
    })
    .add_field(FieldDescriptor::String {
        name: "MAC mismatch\0",
        abbrev: "tezos.error\0",
    })
    .add_field(FieldDescriptor::String {
        name: "Identity required\0",
        abbrev: "tezos.identity_required\0",
    })
    .add_field(FieldDescriptor::String {
        name: "Decrypted message\0",
        abbrev: "tezos.decrypted_msg\0",
    })
    .set_pref_filename(PrefFilenameDescriptor {
        name: "identity_json_file\0",
        title: "Identity JSON file\0",
        description: "JSON file with node identity information\0",
    })
    .set_dissector(DissectorDescriptor {
        display_name: "Tezos\0",
        short_name: "tezos_tcp\0",
        dissector: Box::new(TezosDissector::new()),
    })
    .register()
}
