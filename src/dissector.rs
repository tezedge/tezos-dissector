use wireshark_epan_adapter::{Dissector, DissectorInfo};

pub struct TezosDissector;

impl Dissector for TezosDissector {
    fn prefs_update(&mut self, filenames: Vec<&str>) {
        let identity_path = filenames.first().cloned().unwrap();
        let _ = identity_path;
        // here
    }

    fn recognize(&self, info: DissectorInfo<'_>) -> bool {
        let _ = info;
        // here
        true
    }

    fn consume(&mut self, info: DissectorInfo<'_>) -> usize {
        let _ = info;
        // here
        0
    }
}
