use crate::sys;

/// The data of dissector above the current dissector.
pub enum SuperDissectorData {
    Tcp(*mut sys::tcpinfo),
}

/// The helper provided to dissector.
pub struct Packet {
    _data: SuperDissectorData,
    tvb: *mut sys::tvbuff_t,
}

impl Packet {
    pub(crate) fn new(data: SuperDissectorData, tvb: *mut sys::tvbuff_t) -> Self {
        Packet { _data: data, tvb }
    }

    /// Payload in the packet. The stuff that dissector will parse and present on UI.
    pub fn payload(&self) -> Vec<u8> {
        let length = unsafe { sys::tvb_captured_length(self.tvb) };
        let mut v = Vec::new();
        v.resize(length as _, 0);
        let _ = unsafe { sys::tvb_memcpy(self.tvb, v.as_mut_ptr() as _, 0, length as _) };
        v
    }
}
