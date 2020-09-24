// Copyright (c) SimpleStaking and Tezedge Contributors
// SPDX-License-Identifier: MIT

use wireshark_definitions::TreePresenter;
use wireshark_epan_adapter::{Dissector, dissector::{Packet, Tree, PacketInfo}};
use tezos_conversation::{Context, Identity, proof_of_work::DEFAULT_TARGET};
use std::collections::BTreeMap;

pub struct TezosDissector {
    identity: Option<(Identity, String)>,
    // Each pair of endpoints has its own context.
    // The pair is unordered,
    // so A talk to B is the same conversation as B talks to A.
    // The key is just pointer in memory, so it is invalid when capturing session is closed.
    contexts: BTreeMap<usize, Context>,
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
    fn consume(&mut self, root: &mut Tree, packet: &Packet, packet_info: &PacketInfo) -> usize {
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
            .or_insert_with(|| Context::new(DEFAULT_TARGET));
        if context.add(self.identity.as_ref(), payload.as_ref(), packet_info, root) {
            payload.len()
        } else {
            0
        }
    }
}
