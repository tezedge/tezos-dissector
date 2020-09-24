// Copyright (c) SimpleStaking and Tezedge Contributors
// SPDX-License-Identifier: MIT

use wireshark_definitions::PacketMetadata;
use std::ops::Range;
use super::{
    addresses::{Addresses, Sender},
    direct_buffer::{DirectBuffer, DecryptError},
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

    pub fn new<P>(packet_info: &P, pow_target: f64) -> Self
    where
        P: PacketMetadata,
    {
        ConversationBuffer {
            addresses: Addresses::new(packet_info),
            pow_target,
            incoming: DirectBuffer::new(),
            outgoing: DirectBuffer::new(),
        }
    }

    pub fn consume<P>(&mut self, payload: &[u8], packet_info: &P) -> Result<(), ()>
    where
        P: PacketMetadata,
    {
        let target = self.pow_target;
        let direct_buffer = self.direct_buffer_mut(packet_info);
        let already_checked = direct_buffer.data().len() >= Self::CHECK_RANGE.end;
        direct_buffer.consume(payload, packet_info.frame_number());
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

    pub fn direct_buffer<P>(&self, packet_info: &P) -> &DirectBuffer
    where
        P: PacketMetadata,
    {
        match self.sender(packet_info) {
            Sender::Initiator => &self.incoming,
            Sender::Responder => &self.outgoing,
        }
    }

    pub fn sender<P>(&self, packet_info: &P) -> Sender
    where
        P: PacketMetadata,
    {
        self.addresses.sender(packet_info)
    }

    fn direct_buffer_mut<P>(&mut self, packet_info: &P) -> &mut DirectBuffer
    where
        P: PacketMetadata,
    {
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
