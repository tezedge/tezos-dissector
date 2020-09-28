use wireshark_definitions::{NetworkPacket, SocketAddress};
use std::net::{SocketAddr, IpAddr};
use crate::sys;

pub struct PacketInfo {
    pub pinfo: *mut sys::packet_info,
    pub tvb: *mut sys::tvbuff_t,
}

impl PacketInfo {
    fn inner(&self) -> &sys::packet_info {
        unsafe { &*self.pinfo }
    }

    fn fd(&self) -> &sys::frame_data {
        unsafe { &*self.inner().fd }
    }

    /// The key is unique per source/destination address.
    /// Unordered pair of source/destination can also be used as a key.
    pub fn context_key(&self) -> usize {
        let key = unsafe {
            let conversation = sys::find_or_create_conversation(self.pinfo);
            sys::get_tcp_conversation_data(conversation, self.pinfo)
        };
        key as _
    }
}

impl From<PacketInfo> for NetworkPacket {
    fn from(v: PacketInfo) -> Self {
        NetworkPacket {
            source: read_address(v.inner().src, v.inner().srcport as u16),
            destination: read_address(v.inner().dst, v.inner().destport as u16),
            number: v.fd().num as _,
            payload: {
                let length = unsafe { sys::tvb_captured_length(v.tvb) };
                let mut vec = Vec::new();
                vec.resize(length as _, 0);
                let _ = unsafe { sys::tvb_memcpy(v.tvb, vec.as_mut_ptr() as _, 0, length as _) };
                vec
            },
        }
    }
}

fn read_address(addr: sys::address, port: u16) -> SocketAddress {
    use std::slice;

    let slice = unsafe { slice::from_raw_parts(addr.data as *const u8, addr.len as _) };
    if addr.type_ == sys::address_type_AT_IPv4 as i32 {
        let mut b = [0; 4];
        if slice.len() == 4 {
            b.clone_from_slice(slice);
            SocketAddress::Ip(SocketAddr::new(IpAddr::from(b), port))
        } else {
            SocketAddress::Other {
                ip_type: addr.type_,
                ip: slice.to_owned(),
                port,
            }
        }
    } else if addr.type_ == sys::address_type_AT_IPv6 as i32 {
        let mut b = [0; 16];
        if slice.len() == 16 {
            b.clone_from_slice(slice);
            SocketAddress::Ip(SocketAddr::new(IpAddr::from(b), port))
        } else {
            SocketAddress::Other {
                ip_type: addr.type_,
                ip: slice.to_owned(),
                port,
            }
        }
    } else {
        SocketAddress::Other {
            ip_type: addr.type_,
            ip: slice.to_owned(),
            port,
        }
    }
}
