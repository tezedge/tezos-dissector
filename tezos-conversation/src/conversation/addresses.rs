// Copyright (c) SimpleStaking and Tezedge Contributors
// SPDX-License-Identifier: MIT

use wireshark_definitions::{SocketAddress, PacketMetadata};
use std::fmt;

/// Structure store addresses of first message,
/// for any next message it might determine if sender is initiator or responder
#[derive(Debug)]
pub struct Addresses {
    initiator: SocketAddress,
    responder: SocketAddress,
}

impl fmt::Display for Addresses {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} -> {}", self.initiator, self.responder)
    }
}

impl Addresses {
    pub fn new<P>(packet_info: &P) -> Self
    where
        P: PacketMetadata,
    {
        Addresses {
            initiator: packet_info.source(),
            responder: packet_info.destination(),
        }
    }

    pub fn sender<P>(&self, packet_info: &P) -> Sender
    where
        P: PacketMetadata,
    {
        if self.initiator == packet_info.source() {
            assert_eq!(self.responder, packet_info.destination());
            Sender::Initiator
        } else if self.responder == packet_info.source() {
            assert_eq!(self.initiator, packet_info.destination());
            Sender::Responder
        } else {
            panic!()
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum Sender {
    Initiator,
    Responder,
}
