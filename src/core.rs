use std::{
    ptr,
    os::raw::{c_int, c_void, c_char},
    ffi::CStr,
};
#[rustfmt::skip]
use super::wireshark::{
    ftenum_FT_INT64, ftenum_FT_STRING,

    proto_register_plugin,
    proto_register_protocol, proto_register_field_array, proto_register_subtree_array,
    proto_plugin, hf_register_info, header_field_info,
    field_display_e_BASE_DEC, field_display_e_BASE_NONE, hf_ref_type_HF_REF_TYPE_NONE,

    create_dissector_handle, heur_dissector_add, proto_tree_add_item, proto_item_add_subtree,
    proto_tree_add_int64_format,
    dissector_handle_t, gboolean, tvbuff_t, packet_info, proto_tree,
    heuristic_enable_e_HEURISTIC_ENABLE,

    find_or_create_conversation, conversation_set_dissector, conversation_get_proto_data,
    conversation_add_proto_data,
    ENC_NA,

    get_tcp_conversation_data,

    wmem_allocator_t, wmem_cb_event_t,
    wmem_register_callback, wmem_file_scope,
    _wmem_cb_event_t_WMEM_CB_DESTROY_EVENT as WMEM_CB_DESTROY_EVENT,

    prefs_register_protocol, prefs_register_filename_preference,

    g_print,
};

#[repr(C)]
pub struct TezosDissectorInfo {
    hf_payload_len: c_int,
    hf_packet_counter: c_int,
    hf_connection_msg: c_int,
    hf_decrypted_msg: c_int,
    hf_error: c_int,
    hf_debug: c_int,
}

#[no_mangle]
static plugin_version: &str = concat!(
    env!("CARGO_PKG_VERSION_MAJOR"),
    env!("CARGO_PKG_VERSION_MINOR"),
    "\0"
);

#[no_mangle]
static plugin_want_major: c_int = 3;

#[no_mangle]
static plugin_want_minor: c_int = 3;

static PLUGIN: proto_plugin = proto_plugin {
    register_protoinfo: Some(proto_register_tezos),
    register_handoff: Some(proto_reg_handoff_tezos),
};

static mut TEZOS_HANDLE: dissector_handle_t = ptr::null_mut();

static mut PROTO_TEZOS: c_int = -1;

static mut INFO: TezosDissectorInfo = TezosDissectorInfo {
    hf_payload_len: -1,
    hf_packet_counter: -1,
    hf_connection_msg: -1,
    hf_decrypted_msg: -1,
    hf_error: -1,
    hf_debug: -1,
};

static mut ETT_TEZOS: c_int = -1;

static mut IDENTITY_JSON_FILEPATH: *const c_char = ptr::null();

unsafe extern "C" fn wmem_cb(
    _allocator: *mut wmem_allocator_t,
    ev: wmem_cb_event_t,
    data: *mut c_void,
) -> gboolean {
    match ev {
        WMEM_CB_DESTROY_EVENT => unreachable!(),
        _ => (),
    }

    // call rust
    let _ = data;

    0
}

unsafe extern "C" fn dissect_tezos_old(
    tvb: *mut tvbuff_t,
    pinfo: *mut packet_info,
    tree: *mut proto_tree,
    data: *mut c_void,
) -> c_int {
    let conv = find_or_create_conversation(pinfo);
    let tcpd = get_tcp_conversation_data(conv, pinfo);
    let convd = conversation_get_proto_data(conv, PROTO_TEZOS);
    if !convd.is_null() {
        conversation_add_proto_data(conv, PROTO_TEZOS, std::mem::transmute(1usize));
        wmem_register_callback(wmem_file_scope(), Some(wmem_cb), tcpd as _);
    }

    let ti = proto_tree_add_item(tree, PROTO_TEZOS, tvb, 0, -1, ENC_NA);
    let t_tree = proto_item_add_subtree(ti, ETT_TEZOS);
    proto_tree_add_int64_format(
        t_tree,
        INFO.hf_payload_len,
        tvb,
        0,
        0,
        conv as i64,
        "Tezos conversation: %p\0".as_ptr() as _,
        conv,
    );

    // call rust
    g_print(
        "[TEZOS_DISSECTOR_LOG]: conv: %p %p\n\0".as_ptr() as _,
        wmem_file_scope(),
        conv,
    );
    let _ = data;

    0
}

unsafe extern "C" fn dissect_tezos(
    tvb: *mut tvbuff_t,
    pinfo: *mut packet_info,
    tree: *mut proto_tree,
    data: *mut c_void,
) -> gboolean {
    // It's ours!
    let conv = find_or_create_conversation(pinfo);
    // Mark it as ours.
    conversation_set_dissector(conv, TEZOS_HANDLE);

    let _ = dissect_tezos_old(tvb, pinfo, tree, data);
    1
}

unsafe extern "C" fn proto_register_tezos() {
    PROTO_TEZOS = proto_register_protocol(
        "Tezos Protocol\0".as_ptr() as _,
        "tezos\0".as_ptr() as _,
        "tezos\0".as_ptr() as _,
    );

    let header = |name: &str, abbrev: &str, type_: u32, display: u32| -> header_field_info {
        header_field_info {
            name: name.as_ptr() as _,
            abbrev: abbrev.as_ptr() as _,
            type_: type_,
            display: display as _,
            strings: ptr::null(),
            bitmask: 0,
            blurb: ptr::null(),
            id: -1,
            parent: 0,
            ref_type: hf_ref_type_HF_REF_TYPE_NONE,
            same_name_prev_id: -1,
            same_name_next: ptr::null_mut(),
        }
    };

    let mut hf = [
        hf_register_info {
            p_id: &mut INFO.hf_packet_counter,
            hfinfo: header(
                "Tezos Packet Counter\0",
                "tezos.packet_counter\0",
                ftenum_FT_INT64,
                field_display_e_BASE_DEC,
            ),
        },
        hf_register_info {
            p_id: &mut INFO.hf_payload_len,
            hfinfo: header(
                "Tezos Payload Length\0",
                "tezos.payload_len\0",
                ftenum_FT_INT64,
                field_display_e_BASE_DEC,
            ),
        },
        hf_register_info {
            p_id: &mut INFO.hf_connection_msg,
            hfinfo: header(
                "Tezos Connection Msg\0",
                "tezos.connection_msg\0",
                ftenum_FT_STRING,
                field_display_e_BASE_NONE,
            ),
        },
        hf_register_info {
            p_id: &mut INFO.hf_decrypted_msg,
            hfinfo: header(
                "Tezos Decrypted Msg\0",
                "tezos.decrypted_msg\0",
                ftenum_FT_STRING,
                field_display_e_BASE_NONE,
            ),
        },
        hf_register_info {
            p_id: &mut INFO.hf_error,
            hfinfo: header(
                "Tezos Error\0",
                "tezos.error\0",
                ftenum_FT_STRING,
                field_display_e_BASE_NONE,
            ),
        },
        hf_register_info {
            p_id: &mut INFO.hf_debug,
            hfinfo: header(
                "Tezos Debug\0",
                "tezos.debug\0",
                ftenum_FT_STRING,
                field_display_e_BASE_NONE,
            ),
        },
    ];
    proto_register_field_array(PROTO_TEZOS, hf.as_mut_ptr() as _, hf.len() as _);

    let mut ett = [&mut ETT_TEZOS];
    proto_register_subtree_array(ett.as_mut_ptr() as _, ett.len() as _);

    unsafe extern "C" fn preferences_update_cb() {
        // call rust
        let json_identity_filepath = CStr::from_ptr(IDENTITY_JSON_FILEPATH).to_str().unwrap();
        println!("Tezos identity: {}", json_identity_filepath);
    }

    let tcp_module = prefs_register_protocol(PROTO_TEZOS, Some(preferences_update_cb));
    prefs_register_filename_preference(
        tcp_module,
        "identity_json_file\0".as_ptr() as _,
        "Identity JSON file\0".as_ptr() as _,
        "JSON file with node identity information\0".as_ptr() as _,
        &mut IDENTITY_JSON_FILEPATH,
        0,
    );
}

unsafe extern "C" fn proto_reg_handoff_tezos() {
    TEZOS_HANDLE = create_dissector_handle(Some(dissect_tezos_old), PROTO_TEZOS);
    heur_dissector_add(
        "tcp\0".as_ptr() as _,
        Some(dissect_tezos),
        "Tezos\0".as_ptr() as _,
        "tezos_tcp\0".as_ptr() as _,
        PROTO_TEZOS,
        heuristic_enable_e_HEURISTIC_ENABLE,
    );
}

#[no_mangle]
unsafe extern "C" fn plugin_register() {
    proto_register_plugin(&PLUGIN);
}
