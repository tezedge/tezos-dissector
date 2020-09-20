// Copyright (c) SimpleStaking and Tezedge Contributors
// SPDX-License-Identifier: MIT

use wireshark_epan_adapter::dissector::PacketInfo;
use std::ops::Range;
use super::{
    addresses::{Addresses, Sender},
    direct_buffer::{DirectBuffer, DecryptError},
};
use crate::{
    identity::Decipher,
    proof_of_work::{check_proof_of_work, DEFAULT_TARGET},
};

pub struct ConversationBuffer {
    addresses: Addresses,
    incoming: DirectBuffer,
    outgoing: DirectBuffer,
}

impl ConversationBuffer {
    // 2 bytes chunk length + 2 bytes port = 4
    // 32 bytes public key + 24 bytes proof_of_work = 56
    const CHECK_RANGE: Range<usize> = 4..(4 + 56);

    pub fn new(packet_info: &PacketInfo) -> Self {
        ConversationBuffer {
            addresses: Addresses::new(packet_info),
            incoming: DirectBuffer::new(),
            outgoing: DirectBuffer::new(),
        }
    }

    pub fn consume(&mut self, payload: &[u8], packet_info: &PacketInfo) -> Result<(), ()> {
        let sender = self.sender(packet_info);
        let direct_buffer = self.direct_buffer_mut(packet_info);
        let already_checked = direct_buffer.data().len() >= Self::CHECK_RANGE.end;
        match sender {
            Sender::Initiator => direct_buffer.consume(payload, packet_info.frame_number()),
            Sender::Responder => direct_buffer.consume(payload, packet_info.frame_number()),
        };
        let data = direct_buffer.data();
        // if after consume have enough bytes, let's check the proof of work
        let can_check = data.len() >= Self::CHECK_RANGE.end;
        if !already_checked && can_check {
            check_proof_of_work(&data[Self::CHECK_RANGE], DEFAULT_TARGET)
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

    pub fn direct_buffer(&self, packet_info: &PacketInfo) -> &DirectBuffer {
        match self.sender(packet_info) {
            Sender::Initiator => &self.incoming,
            Sender::Responder => &self.outgoing,
        }
    }

    pub fn sender(&self, packet_info: &PacketInfo) -> Sender {
        self.addresses.sender(packet_info)
    }

    fn direct_buffer_mut(&mut self, packet_info: &PacketInfo) -> &mut DirectBuffer {
        match self.sender(packet_info) {
            Sender::Initiator => &mut self.incoming,
            Sender::Responder => &mut self.outgoing,
        }
    }

    pub fn decrypt(&mut self, decipher: &Decipher) -> Result<(), DecryptError> {
        self.incoming.decrypt(decipher, Sender::Initiator)?;
        self.outgoing.decrypt(decipher, Sender::Responder)?;
        Ok(())
    }
}
