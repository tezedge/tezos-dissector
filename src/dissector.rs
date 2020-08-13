use wireshark_epan_adapter::{Dissector, DissectorInfo};

pub struct TezosDissector;

impl Dissector for TezosDissector {
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
