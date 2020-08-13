use wireshark_epan_adapter::{Dissector, DissectorInfo, sys};
use std::{
    collections::HashMap,
    cell::RefCell,
};

struct Conversation;

pub struct TezosDissector {
    conversations: RefCell<HashMap<*const sys::tcp_analysis, Conversation>>,
}

impl TezosDissector {
    pub fn new() -> Self {
        TezosDissector {
            conversations: RefCell::new(HashMap::new()),
        }
    }
}

impl Dissector for TezosDissector {
    fn prefs_update(&mut self, filenames: Vec<&str>) {
        let _identity_path = filenames.first().cloned().unwrap();
    }

    fn recognize(&mut self, proto: i32, info: DissectorInfo<'_, sys::tcpinfo>) -> usize {
        self.consume(proto, info)
    }

    fn consume(&mut self, proto: i32, info: DissectorInfo<'_, sys::tcpinfo>) -> usize {
        unsafe extern "C" fn wmem_cb(
            _allocator: *mut sys::wmem_allocator_t,
            ev: sys::wmem_cb_event_t,
            data: *mut std::os::raw::c_void,
        ) -> sys::gboolean {
            match ev {
                sys::_wmem_cb_event_t_WMEM_CB_DESTROY_EVENT => unreachable!(),
                _ => (),
            }

            Box::from_raw(*(data as *mut *mut dyn Fn()))();

            0
        }

        unsafe {
            let conv = sys::find_or_create_conversation(info.pinfo);
            let tcpd = sys::get_tcp_conversation_data(conv, info.pinfo);
            let convd = sys::conversation_get_proto_data(conv, proto);
            if convd.is_null() {
                sys::conversation_add_proto_data(conv, proto, std::mem::transmute(1usize));
                sys::wmem_register_callback(sys::wmem_file_scope(), Some(wmem_cb), Box::into_raw(Box::new(Box::new(|| self.conversations.borrow_mut().remove(&(tcpd as _))))) as _);
            }

            let ti = sys::proto_tree_add_item(info.tree, proto, info.tvb, 0, -1, sys::ENC_NA);
            let t_tree = sys::proto_item_add_subtree(ti, info.ett[0]);
            sys::proto_tree_add_int64_format(
                t_tree,
                info.fields["tezos.payload_len\0"],
                info.tvb,
                0,
                0,
                conv as i64,
                "Tezos conversation: %p\0".as_ptr() as _,
                conv,
            );

            sys::tvb_captured_length(info.tvb) as _
        }
    }
}
