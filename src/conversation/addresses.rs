// Copyright (c) SimpleStaking and Tezedge Contributors
// SPDX-License-Identifier: MIT

use wireshark_epan_adapter::dissector::{SocketAddress, PacketInfo};

#[derive(Debug)]
pub struct Addresses {
    initiator: SocketAddress,
    responder: SocketAddress,
}

impl Addresses {
    pub fn new(packet_info: &PacketInfo) -> Self {
        Addresses {
            initiator: packet_info.source(),
            responder: packet_info.destination(),
        }
    }

    pub fn sender(&self, packet_info: &PacketInfo) -> Sender {
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
