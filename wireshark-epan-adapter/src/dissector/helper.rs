use super::PacketInfo;
use crate::{sys, Contexts};

pub enum SuperDissectorData {
    Tcp(*mut sys::tcpinfo),
}

pub struct DissectorHelper {
    _data: SuperDissectorData,
    packet_info: PacketInfo,
    tvb: *mut sys::tvbuff_t,
    contexts: &'static mut Contexts,
}

impl DissectorHelper {
    pub(crate) fn new(
        data: SuperDissectorData,
        packet_info: PacketInfo,
        tvb: *mut sys::tvbuff_t,
        contexts: &'static mut Contexts,
    ) -> Self {
        DissectorHelper {
            _data: data,
            packet_info,
            tvb,
            contexts,
        }
    }

    // safety, C should be the same in `Plugin::new::<C>` and in `DissectorHelper::context::<C>`
    pub fn context<C>(&mut self) -> &mut C
    where
        C: 'static + Default,
    {
        let key = unsafe {
            let pinfo = self.packet_info.inner_mut();
            sys::find_or_create_conversation(pinfo)
        };
        self.contexts.get_or_new(key)
    }

    pub fn packet_info(&self) -> &PacketInfo {
        &self.packet_info
    }

    pub fn payload(&mut self) -> Vec<u8> {
        let length = unsafe { sys::tvb_captured_length(self.tvb) };
        let mut v = Vec::new();
        v.resize(length as _, 0);
        let _ = unsafe { sys::tvb_memcpy(self.tvb, v.as_mut_ptr() as _, 0, length as _) };
        v
    }
}
