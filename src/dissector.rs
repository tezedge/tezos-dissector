// Copyright (c) SimpleStaking and Tezedge Contributors
// SPDX-License-Identifier: MIT

use wireshark_epan_adapter::{
    Dissector,
    dissector::{Packet, Tree, TreePresenter, PacketInfo},
};
use std::collections::BTreeMap;
use super::{conversation::{Context, ErrorPosition, Sender}, identity::Identity};

pub struct TezosDissector {
    identity: Option<(Identity, String)>,
    // Each pair of endpoints has its own context.
    // The pair is unordered,
    // so A talk to B is the same conversation as B talks to A.
    // The key is just pointer in memory, so it is invalid when capturing session is closed.
    contexts: BTreeMap<usize, ContextExt>,
}

struct ContextExt {
    inner: Context,
    incoming_frame_result: Result<(), ErrorPosition>,
    outgoing_frame_result: Result<(), ErrorPosition>,
}

impl ContextExt {
    pub fn new(inner: Context) -> Self {
        ContextExt {
            inner,
            incoming_frame_result: Ok(()),
            outgoing_frame_result: Ok(()),
        }
    }

    /// The context becomes invalid if the inner is invalid or
    /// if the decryption error occurs in some previous frame.
    /// If the frame number is equal to the frame where error occurs,
    /// the context still valid, but after that it is invalid.
    /// Let's show the error message once.
    fn invalid(&self, packet_info: &PacketInfo) -> bool {
        let i_error = self.incoming_frame_result
            .as_ref()
            .err()
            .map(|ref e| self.inner.after(packet_info, e))
            .unwrap_or(false);
        let o_error = self.outgoing_frame_result
            .as_ref()
            .err()
            .map(|ref e| self.inner.after(packet_info, e))
            .unwrap_or(false);
        i_error || o_error || self.inner.invalid()
    }

    pub fn visualize<T>(
        &mut self,
        packet_length: usize,
        packet_info: &PacketInfo,
        root: &mut T,
    ) -> usize
    where
        T: TreePresenter,
    {
        // the context might become invalid if the conversation is not tezos,
        // or if decryption error occurs
        if !self.invalid(packet_info) {
            match self.inner.visualize(packet_length, packet_info, root) {
                Ok(()) => (),
                Err(r) => match r.sender {
                    Sender::Initiator => self.incoming_frame_result = Err(r),
                    Sender::Responder => self.outgoing_frame_result = Err(r),
                },
            };
            packet_length
        } else {
            0
        }
    }
}

impl TezosDissector {
    pub fn new() -> Self {
        TezosDissector {
            identity: None,
            contexts: BTreeMap::new(),
        }
    }
}

impl Dissector for TezosDissector {
    // This method called by the wireshark when the user choose the identity file.
    fn prefs_update(&mut self, filenames: Vec<&str>) {
        if let Some(identity_path) = filenames.first().cloned() {
            if !identity_path.is_empty() {
                // read the identity from the file
                self.identity = Identity::from_path(identity_path)
                    .map_err(|e| {
                        log::error!("Identity: {}", e);
                        e
                    })
                    .map(|i| (i, identity_path.to_owned()))
                    .ok();
            }
        }
    }

    // This method called by the wireshark when a new packet just arrive,
    // or when the user click on the packet.
    fn consume(
        &mut self,
        root: &mut Tree,
        packet: &Packet,
        packet_info: &PacketInfo,
    ) -> usize {
        self.consume_polymorphic::<Tree>(root, packet, packet_info)
    }

    // This method called by the wireshark when the user
    // closing current capturing session
    fn cleanup(&mut self) {
        self.contexts.clear();
    }
}

impl TezosDissector {
    /// needed for tests, to use moc instead of `Tree`
    fn consume_polymorphic<T>(
        &mut self,
        root: &mut Tree,
        packet: &Packet,
        packet_info: &PacketInfo,
    ) -> usize
    where
        T: TreePresenter,
    {
        // get the data
        let payload = packet.payload();
        // retrieve or create a new context for the conversation
        let context_key = packet_info.context_key();
        let context = self
            .contexts
            .entry(context_key)
            .or_insert_with(|| ContextExt::new(Context::new(packet_info)));
        if !packet_info.visited() {
            // consume each packet only once
            context
                .inner
                .consume(payload.as_ref(), packet_info, self.identity.as_ref());
        }
        context.visualize(payload.len(), packet_info, root)
    }
}
