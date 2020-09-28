// Copyright (c) SimpleStaking and Tezedge Contributors
// SPDX-License-Identifier: MIT

use wireshark_definitions::{TreePresenter, NetworkPacket};
use wireshark_epan_adapter::{Dissector, Tree};
use tezos_conversation::{Conversation, BinaryChunkStorage, Identity, proof_of_work::DEFAULT_TARGET};
use std::collections::BTreeMap;

pub struct TezosDissector {
    identity: Option<(Identity, String)>,
    // Each pair of endpoints has its own context.
    // The pair is unordered,
    // so A talk to B is the same conversation as B talks to A.
    // The key is just pointer in memory, so it is invalid when capturing session is closed.
    conversations: BTreeMap<usize, Conversation>,
}

impl TezosDissector {
    pub fn new() -> Self {
        TezosDissector {
            identity: None,
            conversations: BTreeMap::new(),
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
    fn consume(&mut self, root: &mut Tree, packet: NetworkPacket, c_id: usize) -> usize {
        self.consume_polymorphic::<Tree>(root, packet, c_id)
    }

    // This method called by the wireshark when the user
    // closing current capturing session
    fn cleanup(&mut self) {
        self.conversations.clear();
    }
}

impl TezosDissector {
    /// needed for tests, to use moc instead of `Tree`
    fn consume_polymorphic<T>(
        &mut self,
        root: &mut Tree,
        packet: NetworkPacket,
        c_id: usize,
    ) -> usize
    where
        T: TreePresenter,
    {
        // get the data
        // retrieve or create a new context for the conversation
        let conversation = self
            .conversations
            .entry(c_id)
            .or_insert_with(|| Conversation::new(DEFAULT_TARGET));
        let _ = conversation.add(self.identity.as_ref(), &packet);
        if conversation.visualize(&packet, &BinaryChunkStorage::new(), root) {
            packet.payload.len()
        } else {
            0
        }
    }
}
