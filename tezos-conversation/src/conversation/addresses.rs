// Copyright (c) SimpleStaking and Tezedge Contributors
// SPDX-License-Identifier: MIT

use wireshark_definitions::{SocketAddress, NetworkPacket};
use std::fmt;

/// Structure store addresses of first message,
/// for any next message it might determine if sender is initiator or responder
#[derive(Debug)]
pub struct Addresses {
    initiator: SocketAddress,
    responder: SocketAddress,
}

pub struct ChunkMetadata {
    pub source: SocketAddress,
    pub destination: SocketAddress,
    pub sender: Sender,
}

impl fmt::Display for Addresses {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} -> {}", self.initiator, self.responder)
    }
}

impl Addresses {
    pub fn new(packet: &NetworkPacket) -> Self {
        Addresses {
            initiator: packet.source.clone(),
            responder: packet.destination.clone(),
        }
    }

    pub fn sender(&self, packet: &NetworkPacket) -> Sender {
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

    pub fn metadata(&self, packet: &NetworkPacket) -> ChunkMetadata {
        let sender = self.sender(packet);
        match &sender {
            &Sender::Initiator => ChunkMetadata {
                source: self.initiator.clone(),
                destination: self.responder.clone(),
                sender,
            },
            &Sender::Responder => ChunkMetadata {
                source: self.responder.clone(),
                destination: self.initiator.clone(),
                sender,
            },
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Sender {
    Initiator,
    Responder,
}
