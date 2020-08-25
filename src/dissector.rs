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
    fn prefs_update(&mut self, filenames: Vec<&str>) {
        if let Some(identity_path) = filenames.first().cloned() {
            if !identity_path.is_empty() {
                self.identity = Identity::from_path(identity_path)
                    .map_err(|e| {
                        log::error!("Identity: {}", e);
                        e
                    })
                    .ok();
            }
        }
    }

    fn consume(
        &mut self,
        helper: &mut DissectorHelper,
        root: &mut Tree,
        packet_info: &PacketInfo,
    ) -> usize {
        let payload = helper.payload();
        let context_key = helper.context_key(packet_info);
        let context = self
            .contexts
            .entry(context_key)
            .or_insert_with(|| Context::new(packet_info));
        if !packet_info.visited() {
            context.consume(payload.as_ref(), packet_info, self.identity.as_ref());
        }
        if !context.invalid() {
            context.visualize(payload.len(), packet_info, root);
            payload.len()
        } else {
            0
        }
    }

    fn cleanup(&mut self) {
        self.contexts.clear();
    }
}
