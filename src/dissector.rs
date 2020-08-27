// Copyright (c) SimpleStaking and Tezedge Contributors
// SPDX-License-Identifier: MIT

use wireshark_epan_adapter::{
    Dissector,
    dissector::{DissectorHelper, Tree, PacketInfo},
};
use std::collections::BTreeMap;
use super::{conversation::Context, identity::Identity};

pub struct TezosDissector {
    identity: Option<Identity>,
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
                    .ok();
            }
        }
    }

    // This method called by the wireshark when a new packet just arrive,
    // or when the user click on the packet.
    fn consume(
        &mut self,
        helper: &mut DissectorHelper,
        root: &mut Tree,
        packet_info: &PacketInfo,
    ) -> usize {
        // get the data
        let payload = helper.payload();
        // retrieve or create a new context for the conversation
        let context_key = helper.context_key(packet_info);
        let context = self
            .contexts
            .entry(context_key)
            .or_insert_with(|| Context::new(packet_info));
        if !packet_info.visited() {
            // consume each packet only once
            context.consume(payload.as_ref(), packet_info, self.identity.as_ref());
        }
        // the context might become invalid if the conversation is not tezos
        if !context.invalid() {
            context.visualize(payload.len(), packet_info, root);
            payload.len()
        } else {
            0
        }
    }

    // This method called by the wireshark when the user
    // closing current capturing session
    fn cleanup(&mut self) {
        self.contexts.clear();
    }
}
