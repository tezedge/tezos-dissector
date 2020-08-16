use std::{
    convert::TryFrom,
    net::{SocketAddr, IpAddr},
};
use crate::sys;

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

    pub fn destination(&self) -> Result<SocketAddr, AddressConvertError> {
        Ok(SocketAddr::new(
            IpAddr::try_from(self.inner().dst)?,
            self.inner().destport as u16,
        ))
    }

    pub fn source(&self) -> Result<SocketAddr, AddressConvertError> {
        Ok(SocketAddr::new(
            IpAddr::try_from(self.inner().src)?,
            self.inner().srcport as u16,
        ))
    }

    pub fn frame_number(&self) -> u64 {
        self.fd().num as _
    }

    pub fn visited(&self) -> bool {
        self.fd().visited() != 0
    }
}

#[derive(Debug)]
pub enum AddressConvertError {
    AddressType,
    AddressLength,
}

impl TryFrom<sys::address> for IpAddr {
    type Error = AddressConvertError;

    fn try_from(addr: sys::address) -> Result<Self, Self::Error> {
        use std::slice;

        let slice = unsafe { slice::from_raw_parts(addr.data as *const u8, addr.len as _) };
        match addr.type_ as u32 {
            sys::address_type_AT_IPv4 => {
                let mut b = [0; 4];
                if slice.len() == 4 {
                    b.clone_from_slice(slice);
                    Ok(IpAddr::from(b))
                } else {
                    Err(AddressConvertError::AddressLength)
                }
            },
            sys::address_type_AT_IPv6 => {
                let mut b = [0; 16];
                if slice.len() == 16 {
                    b.clone_from_slice(slice);
                    Ok(IpAddr::from(b))
                } else {
                    Err(AddressConvertError::AddressLength)
                }
            },
            _ => Err(AddressConvertError::AddressType)?,
        }
    }
}
