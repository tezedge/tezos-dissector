use super::{PacketInfo, DissectorTree};
use crate::sys;

pub enum SuperDissectorData {
    Tcp(*mut sys::tcpinfo),
}

//#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
//pub struct ConversationKey(*mut sys::tcp_analysis);

pub struct Context<C> {
    inner: *mut Option<C>,
}

impl<C> AsMut<Option<C>> for Context<C> {
    fn as_mut(&mut self) -> &mut Option<C> {
        unsafe { &mut *self.inner }
    }
}

pub struct DissectorHelper {
    _data: SuperDissectorData,
    proto_handle: i32,
    packet_info: PacketInfo,
    tvb: *mut sys::tvbuff_t,
    tree: DissectorTree,
}

impl DissectorHelper {
    pub(crate) fn new(
        data: SuperDissectorData,
        proto_handle: i32,
        packet_info: PacketInfo,
        tvb: *mut sys::tvbuff_t,
        tree: DissectorTree,
    ) -> Self {
        DissectorHelper {
            _data: data,
            proto_handle,
            packet_info,
            tvb,
            tree,
        }
    }

    pub fn conversation_context<C>(&mut self) -> Context<C> {
        use std::mem;

        unsafe {
            let pinfo = self.packet_info.inner_mut();
            let conversation = sys::find_or_create_conversation(pinfo);
            //let tcp_data = sys::get_tcp_conversation_data(conversation, pinfo);
            //let key = ConversationKey(tcp_data);
            let mut data = sys::conversation_get_proto_data(conversation, self.proto_handle);
            if data.is_null() {
                // TODO: alignment might be an issue
                // TODO: should set to None before deallocation, add wmem callback
                data = sys::wmem_alloc(sys::wmem_file_scope(), mem::size_of::<Option<C>>() as _);
                sys::memset(data, 0, mem::size_of::<Option<C>>() as _);
                sys::conversation_add_proto_data(conversation, self.proto_handle, data);
            }
            Context { inner: data as _ }
        }
    }

    pub fn packet_info(&self) -> &PacketInfo {
        &self.packet_info
    }

    pub fn tree_mut(&mut self) -> &mut DissectorTree {
        &mut self.tree
    }

    pub fn payload(&mut self) -> Vec<u8> {
        let length = unsafe { sys::tvb_captured_length(self.tvb) };
        let mut v = Vec::new();
        v.resize(length as _, 0);
        let _ = unsafe { sys::tvb_memcpy(self.tvb, v.as_mut_ptr() as _, 0, length as _) };
        v
    }
}
