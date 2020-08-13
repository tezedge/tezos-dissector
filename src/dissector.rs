use wireshark_epan_adapter::{Dissector, DissectorInfo, sys};

pub struct TezosDissector;

impl Dissector for TezosDissector {
    fn prefs_update(&mut self, filenames: Vec<&str>) {
        let identity_path = filenames.first().cloned().unwrap();
        let _ = identity_path;
        // here
    }

    fn recognize(&mut self, info: DissectorInfo<'_, sys::tcpinfo>) -> usize {
        let _ = info;
        // here
        info.tvb.length as _
    }

    fn consume(&mut self, info: DissectorInfo<'_, sys::tcpinfo>) -> usize {
        let _ = info;
        // here
        info.tvb.length as _
    }
}
