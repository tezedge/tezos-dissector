use super::PacketInfo;
use crate::sys;

/// The data of dissector above the current dissector.
pub enum SuperDissectorData {
    Tcp(*mut sys::tcpinfo),
}

/// The helper provided to dissector.
pub struct DissectorHelper {
    _data: SuperDissectorData,
    tvb: *mut sys::tvbuff_t,
}

impl DissectorHelper {
    pub(crate) fn new(data: SuperDissectorData, tvb: *mut sys::tvbuff_t) -> Self {
        DissectorHelper { _data: data, tvb }
    }

    /// The key is unique per source/destination address.
    /// Unordered pair of source/destination can also be used as a key.
    pub fn context_key(&mut self, packet_info: &PacketInfo) -> usize {
        let pinfo = packet_info.inner() as *const _ as *mut _;
        let key = unsafe {
            let conversation = sys::find_or_create_conversation(pinfo);
            sys::get_tcp_conversation_data(conversation, pinfo)
        };
        key as _
    }

    /// Payload in the packet. The stuff that dissector will parse and present on UI.
    pub fn payload(&mut self) -> Vec<u8> {
        let length = unsafe { sys::tvb_captured_length(self.tvb) };
        let mut v = Vec::new();
        v.resize(length as _, 0);
        let _ = unsafe { sys::tvb_memcpy(self.tvb, v.as_mut_ptr() as _, 0, length as _) };
        v
    }
}
