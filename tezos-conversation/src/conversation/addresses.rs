// Copyright (c) SimpleStaking and Tezedge Contributors
// SPDX-License-Identifier: MIT

use wireshark_definitions::NetworkPacket;
use std::{fmt, net::SocketAddr};

pub struct Packet {
    pub destination: SocketAddr,
    pub source: SocketAddr,
    pub number: u64,
    pub payload: Vec<u8>,
}

impl From<NetworkPacket> for Packet {
    fn from(v: NetworkPacket) -> Self {
        Packet {
            destination: v.destination.ip(),
            source: v.source.ip(),
            number: v.number,
            payload: v.payload,
        }
    }
}

/// Structure store addresses of first message,
/// for any next message it might determine if sender is initiator or responder
#[derive(Debug, Clone)]
pub struct Addresses {
    initiator: SocketAddr,
    responder: SocketAddr,
}

impl fmt::Display for Addresses {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} -> {}", self.initiator, self.responder)
    }
}

impl Addresses {
    pub fn new(packet: &Packet) -> Self {
        Addresses {
            initiator: packet.source.clone(),
            responder: packet.destination.clone(),
        }
    }

    pub fn sender(&self, packet: &Packet) -> Sender {
        if self.initiator == packet.source {
            assert_eq!(self.responder, packet.destination);
            Sender::Initiator
        } else if self.responder == packet.source {
            assert_eq!(self.initiator, packet.destination);
            Sender::Responder
        } else {
            panic!()
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Sender {
    Initiator,
    Responder,
}
