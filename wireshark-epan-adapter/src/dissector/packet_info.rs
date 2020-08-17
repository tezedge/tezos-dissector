use std::{fmt, net::{SocketAddr, IpAddr}};
use crate::sys;

/// It might panic or return error, but let's do not care
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub enum SocketAddress {
    Ip(SocketAddr),
    Other {
        ip_type: i32,
        ip: Vec<u8>,
        port: u16,
    }
}

impl fmt::Display for SocketAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            &SocketAddress::Ip(ref a) => write!(f, "{}", a),
            &SocketAddress::Other {
                ref ip_type,
                ref ip,
                ref port,
            } => write!(f, "Unknown[{}]:{}:{}", *ip_type, hex::encode(ip), *port),
        }
    }
}

pub struct PacketInfo {
    inner: *mut sys::packet_info,
}

impl PacketInfo {
    pub(crate) fn new(raw: *mut sys::packet_info) -> Self {
        PacketInfo { inner: raw }
    }

    pub(crate) fn inner(&self) -> &sys::packet_info {
        unsafe { &*self.inner }
    }

    fn fd(&self) -> &sys::frame_data {
        unsafe { &*self.inner().fd }
    }

    pub fn destination(&self) -> SocketAddress {
        read_address(self.inner().dst, self.inner().destport as u16)
    }

    pub fn source(&self) -> SocketAddress {
        read_address(self.inner().src, self.inner().srcport as u16)
    }

    pub fn frame_number(&self) -> u64 {
        self.fd().num as _
    }

    pub fn visited(&self) -> bool {
        self.fd().visited() != 0
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
