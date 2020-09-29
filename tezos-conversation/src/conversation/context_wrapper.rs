use wireshark_definitions::{NetworkPacket, TreePresenter, SocketAddress};
use tezos_messages::p2p::binary_message::BinaryChunk;
use std::{task::Poll, collections::BTreeMap, ops::Range};
use super::{
    context::{ContextInner, ErrorPosition},
    addresses::Sender,
};
use crate::identity::Identity;

pub struct BinaryChunkMetadata {
    pub initiator: SocketAddress,
    pub responder: SocketAddress,
    pub offset: usize,
    pub sender: Sender,
    pub encrypted: bool,
    pub timestamp: i64,
}

pub trait BinaryChunkProvider {
    fn binary_chunk_content(&self, index: usize, sender: Sender) -> &[u8];
}

pub struct BinaryChunkStorage {
    from_initiator: Vec<Vec<u8>>,
    from_responder: Vec<Vec<u8>>,
}

impl BinaryChunkStorage {
    pub fn new() -> Self {
        BinaryChunkStorage {
            from_initiator: Vec::new(),
            from_responder: Vec::new(),
        }
    }
}

impl BinaryChunkProvider for BinaryChunkStorage {
    fn binary_chunk_content(&self, index: usize, sender: Sender) -> &[u8] {
        match sender {
            Sender::Initiator => self.from_initiator[index].as_slice(),
            Sender::Responder => self.from_responder[index].as_slice(),
        }
    }
}

pub struct Conversation {
    inner: Option<ContextInner>,
    pow_target: f64,
    packet_ranges: BTreeMap<u64, Range<usize>>,
    incoming_frame_result: Result<(), ErrorPosition>,
    outgoing_frame_result: Result<(), ErrorPosition>,
}

impl Conversation {
    pub fn new(pow_target: f64) -> Self {
        Conversation {
            inner: None,
            pow_target,
            packet_ranges: BTreeMap::new(),
            incoming_frame_result: Ok(()),
            outgoing_frame_result: Ok(()),
        }
    }

    /// The context becomes invalid if the inner is invalid or
    /// if the decryption error occurs in some previous frame.
    /// If the frame number is equal to the frame where error occurs,
    /// the context still valid, but after that it is invalid.
    /// Let's show the error message once.
    fn invalid(&self, packet: &NetworkPacket) -> bool {
        if let &Some(ref inner) = &self.inner {
            let i_error = self
                .incoming_frame_result
                .as_ref()
                .err()
                .map(|ref e| inner.after(packet, e))
                .unwrap_or(false);
            let o_error = self
                .outgoing_frame_result
                .as_ref()
                .err()
                .map(|ref e| inner.after(packet, e))
                .unwrap_or(false);
            i_error || o_error || inner.invalid()
        } else {
            false
        }
    }

    pub fn add(
        &mut self,
        identity: Option<&(Identity, String)>,
        packet: &NetworkPacket,
    ) -> Poll<Vec<(BinaryChunkMetadata, BinaryChunk)>> {
        let pow_target = self.pow_target;
        let inner = self.inner.get_or_insert_with(|| ContextInner::new(packet, pow_target));
        if let Some(space) = inner.consume(packet, identity) {
            self.packet_ranges.insert(packet.number, space);
        }
        // TODO: return proper chunks data
        Poll::Pending
    }

    pub fn visualize<P, T>(&mut self, packet: &NetworkPacket, provider: &P, output: &mut T) -> bool
    where
        P: BinaryChunkProvider,
        T: TreePresenter,
    {
        // TODO: use the provider
        let _ = provider;

        // the context might become invalid if the conversation is not tezos,
        // or if decryption error occurs
        if !self.invalid(packet) {
            if let Some(range) = self.packet_ranges.get(&packet.number) {
                match self.inner.as_mut().unwrap().visualize(packet, range.start, output) {
                    Ok(()) => (),
                    Err(r) => match r.sender {
                        Sender::Initiator => self.incoming_frame_result = Err(r),
                        Sender::Responder => self.outgoing_frame_result = Err(r),
                    },
                };
            }
            true
        } else {
            false
        }
    }
}
