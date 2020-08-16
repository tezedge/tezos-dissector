use wireshark_epan_adapter::{Dissector, dissector::{DissectorHelper, Tree, PacketInfo}};
use super::{context::Context, identity::Identity};

pub struct TezosDissector {
    identity: Option<Identity>,
}

impl TezosDissector {
    pub fn new() -> Self {
        TezosDissector { identity: None }
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
        let context = helper.context::<Context>(packet_info);
        context.consume(payload.as_ref(), packet_info);
        if !context.invalid() {
            context.visualize(payload.as_ref(), packet_info, root, &self.identity);
            payload.len()
        } else {
            0
        }
    }
}
