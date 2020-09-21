use std::{
    fmt,
    net::{SocketAddr, IpAddr},
};
use crate::sys;

/// The most common socket address is ip (v4 or v6 and port),
/// but also it might be some other kind of address.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub enum SocketAddress {
    Ip(SocketAddr),
    Other {
        ip_type: i32,
        ip: Vec<u8>,
        port: u16,
    },
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

pub trait PacketMetadata {
    fn destination(&self) -> SocketAddress;
    fn source(&self) -> SocketAddress;
    fn frame_number(&self) -> u64;
    fn visited(&self) -> bool;
}

/// Provides information about the packet.
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

    /// The key is unique per source/destination address.
    /// Unordered pair of source/destination can also be used as a key.
    pub fn context_key(&self) -> usize {
        let key = unsafe {
            let conversation = sys::find_or_create_conversation(self.inner);
            sys::get_tcp_conversation_data(conversation, self.inner)
        };
        key as _
    }
}

impl PacketMetadata for PacketInfo {
    /// Destination address.
    fn destination(&self) -> SocketAddress {
        read_address(self.inner().dst, self.inner().destport as u16)
    }

    /// Source address.
    fn source(&self) -> SocketAddress {
        read_address(self.inner().src, self.inner().srcport as u16)
    }

    /// Just the number by the order. First captures packet has number 1, second 2, and so on.
    /// Used as a identification of the packet.
    fn frame_number(&self) -> u64 {
        self.fd().num as _
    }

    /// Is this packet was already processed by this dissector.
    fn visited(&self) -> bool {
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
