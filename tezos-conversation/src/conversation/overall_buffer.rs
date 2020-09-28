// Copyright (c) SimpleStaking and Tezedge Contributors
// SPDX-License-Identifier: MIT

use wireshark_definitions::NetworkPacket;
use std::ops::Range;
use super::{
    addresses::{Addresses, Sender},
    direct_buffer::{DirectBuffer, ChunkPosition},
};
use crate::{
    identity::Decipher,
    proof_of_work::check_proof_of_work,
};

pub struct ConversationBuffer {
    addresses: Addresses,
    pow_target: f64,
    incoming: DirectBuffer,
    outgoing: DirectBuffer,
}

impl ConversationBuffer {
    // 2 bytes chunk length + 2 bytes port = 4
    // 32 bytes public key + 24 bytes proof_of_work = 56
    const CHECK_RANGE: Range<usize> = 4..(4 + 56);

    pub fn new(packet: &NetworkPacket, pow_target: f64) -> Self {
        ConversationBuffer {
            addresses: Addresses::new(packet),
            pow_target,
            incoming: DirectBuffer::new(),
            outgoing: DirectBuffer::new(),
        }
    }

    pub fn consume(&mut self, packet: &NetworkPacket) -> Result<(), ()> {
        let target = self.pow_target;
        let sender = self.sender(packet);
        let direct_buffer = self.direct_buffer_mut(&sender);
        let already_checked = direct_buffer.data().len() >= Self::CHECK_RANGE.end;
        direct_buffer.consume(packet.payload.as_ref(), packet.number);
        let data = direct_buffer.data();
        // if after consume have enough bytes, let's check the proof of work
        let can_check = data.len() >= Self::CHECK_RANGE.end;
        if !already_checked && can_check {
            check_proof_of_work(&data[Self::CHECK_RANGE], target)
        } else {
            Ok(())
        }
    }

    pub fn id(&self) -> String {
        format!("{}", self.addresses)
    }

    pub fn can_upgrade(&self) -> Option<(&[u8], &[u8])> {
        match (
            self.incoming.chunks().first(),
            self.outgoing.chunks().first(),
        ) {
            (Some(i), Some(o)) => {
                let can = self.incoming.data().len() >= i.range().end
                    && i.range().len() >= Self::CHECK_RANGE.end
                    && self.outgoing.data().len() >= o.range().end
                    && o.range().len() >= Self::CHECK_RANGE.end;
                if can {
                    let initiator = &self.incoming.data()[self.incoming.chunks()[0].range()];
                    let responder = &self.outgoing.data()[self.outgoing.chunks()[0].range()];
                    Some((initiator, responder))
                } else {
                    None
                }
            },
            _ => None,
        }
    }

    pub fn direct_buffer(&self, sender: &Sender) -> &DirectBuffer {
        match sender {
            &Sender::Initiator => &self.incoming,
            &Sender::Responder => &self.outgoing,
        }
    }

    fn direct_buffer_mut(&mut self, sender: &Sender) -> &mut DirectBuffer {
        match sender {
            &Sender::Initiator => &mut self.incoming,
            &Sender::Responder => &mut self.outgoing,
        }
    }

    pub fn sender(&self, packet: &NetworkPacket) -> Sender {
        self.addresses.sender(packet)
    }

    pub fn decrypt(&mut self, decipher: &Decipher) -> Result<(), ChunkPosition> {
        self.incoming.decrypt(decipher, Sender::Initiator)?;
        self.outgoing.decrypt(decipher, Sender::Responder)?;
        Ok(())
    }
}
