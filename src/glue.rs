use std::{
    ptr,
    os::raw::{c_int, c_void},
};
use super::ffi::{
    proto::{
        proto_register_protocol,
        proto_register_field_array,
        proto_register_subtree_array,
        hf_register_info,
        header_field_info,
        field_display_e_BASE_DEC,
        field_display_e_BASE_NONE,
        hf_ref_type_HF_REF_TYPE_NONE,
    },
    packet::{
        dissector_handle_t,
        gboolean,
        tvbuff_t,
        packet_info,
        proto_tree,
        create_dissector_handle,
        heur_dissector_add,
        heuristic_enable_e_HEURISTIC_ENABLE,
    },
    ftypes::{ftenum_FT_INT64, ftenum_FT_STRING},
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

unsafe extern "C" fn dissect_tezos_old(
    tvb: *mut tvbuff_t,
    pinfo: *mut packet_info,
    tree: *mut proto_tree,
    data: *mut c_void,
) -> c_int {
    let _ = (tvb, pinfo, tree, data);
    unimplemented!()
}

unsafe extern "C" fn dissect_tezos(
    tvb: *mut tvbuff_t,
    pinfo: *mut packet_info,
    tree: *mut proto_tree,
    data: *mut c_void,
) -> gboolean {
    //conversation_t *conv = NULL;

	/*** It's ours! ***/
	//conv = find_or_create_conversation(pinfo);
	/* Mark it as ours. */
    //conversation_set_dissector(conv, TEZOS_HANDLE);

    let _ = dissect_tezos_old(tvb, pinfo, tree, data);
    1
}

#[no_mangle]
unsafe extern "C" fn proto_register_tezos() {
    PROTO_TEZOS = proto_register_protocol(
        "Tezos Protocol".as_ptr() as _,
        "tezos".as_ptr() as _,
        "tezos".as_ptr() as _,
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
            p_id: &mut INFO.hf_payload_len,
            hfinfo: header(
                "Tezos Packet Counter",
                "tezos.packet_counter",
                ftenum_FT_INT64,
                field_display_e_BASE_DEC,
            ),
        },
        hf_register_info {
            p_id: &mut INFO.hf_payload_len,
            hfinfo: header(
                "Tezos Payload Length",
                "tezos.payload_len",
                ftenum_FT_INT64,
                field_display_e_BASE_DEC,
            ),
        },
        hf_register_info {
            p_id: &mut INFO.hf_payload_len,
            hfinfo: header(
                "Tezos Connection Msg",
                "tezos.connection_msg",
                ftenum_FT_STRING,
                field_display_e_BASE_NONE,
            ),
        },
        hf_register_info {
            p_id: &mut INFO.hf_payload_len,
            hfinfo: header(
                "Tezos Decrypted Msg",
                "tezos.decrypted_msg",
                ftenum_FT_STRING,
                field_display_e_BASE_NONE,
            ),
        },
        hf_register_info {
            p_id: &mut INFO.hf_payload_len,
            hfinfo: header(
                "Tezos Error",
                "tezos.error",
                ftenum_FT_STRING,
                field_display_e_BASE_NONE,
            ),
        },
        hf_register_info {
            p_id: &mut INFO.hf_payload_len,
            hfinfo: header(
                "Tezos Debug",
                "tezos.debug",
                ftenum_FT_STRING,
                field_display_e_BASE_NONE,
            ),
        },
    ];

    let mut ett = [&mut ETT_TEZOS];

    proto_register_field_array(PROTO_TEZOS, hf.as_mut_ptr() as _, hf.len() as _);
    proto_register_subtree_array(ett.as_mut_ptr() as _, ett.len() as _);
}

#[no_mangle]
unsafe extern "C" fn proto_reg_handoff() {
    TEZOS_HANDLE = create_dissector_handle(Some(dissect_tezos_old), PROTO_TEZOS);
    heur_dissector_add(
        "tcp".as_ptr() as _,
        Some(dissect_tezos),
        "Tezos".as_ptr() as _,
        "tezos_tcp".as_ptr() as _,
        PROTO_TEZOS, heuristic_enable_e_HEURISTIC_ENABLE);
}
