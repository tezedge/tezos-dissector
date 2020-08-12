use super::wireshark::{tcp_analysis, tvbuff_t, proto_tree, packet_info};
use super::core::TezosDissectorInfo;
use std::path::Path;

pub fn dissect_packet(
    info_handles: &TezosDissectorInfo,
    buffer: &mut tvbuff_t,
    tree: &mut proto_tree,
    pinfo: &packet_info,
    key: &tcp_analysis,
) -> usize {
    let _ = (info_handles, buffer, tree, pinfo, key);
    // unimplemented!()
    0
}

pub fn free(key: &tcp_analysis) {
    let _ = key;
    // unimplemented!()
}

pub fn preferences_update<P>(identity_path: P)
where
    P: AsRef<Path>,
{
    let _ = identity_path.as_ref();
    // unimplemented!()
}
