use super::TezosDissector;

#[rustfmt::skip]
use wireshark_epan_adapter::{
    EpanPlugin, EpanNameDescriptor, EpanFieldDescriptor,
    EpanPrefFilenameDescriptor,
    EpanDissectorDescriptor,
};

#[no_mangle]
static plugin_version: &str = concat!(env!("CARGO_PKG_VERSION"), "\0");

#[no_mangle]
static plugin_want_major: i32 = 3;

#[no_mangle]
static plugin_want_minor: i32 = 2;

#[no_mangle]
extern "C" fn plugin_register() {
    EpanPlugin::new(EpanNameDescriptor {
        name: "Tezos Protocol\0",
        short_name: "tezos\0",
        filter_name: "tezos\0",
    })
    .add_field(EpanFieldDescriptor::Int64Dec {
        name: "Tezos Packet Counter\0",
        abbrev: "tezos.packet_counter\0",
    })
    .add_field(EpanFieldDescriptor::Int64Dec {
        name: "Tezos Payload Length\0",
        abbrev: "tezos.payload_len\0",
    })
    .add_field(EpanFieldDescriptor::String {
        name: "Tezos Connection Msg\0",
        abbrev: "tezos.connection_msg\0",
    })
    .add_field(EpanFieldDescriptor::String {
        name: "Tezos Decrypted Msg\0",
        abbrev: "tezos.decrypted_msg\0",
    })
    .add_field(EpanFieldDescriptor::String {
        name: "Tezos Error\0",
        abbrev: "tezos.error\0",
    })
    .add_field(EpanFieldDescriptor::String {
        name: "Tezos Debug\0",
        abbrev: "tezos.debug\0",
    })
    .set_ett_number(1)
    .set_pref_filename(EpanPrefFilenameDescriptor {
        name: "identity_json_file\0",
        title: "Identity JSON file\0",
        description: "JSON file with node identity information\0",
    })
    .set_dissector(EpanDissectorDescriptor {
        name: "tcp\0",
        display_name: "Tezos\0",
        short_name: "tezos_tcp\0",
        dissector: Box::new(TezosDissector),
    })
    .register()
}
