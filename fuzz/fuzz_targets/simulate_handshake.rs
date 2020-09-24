#![no_main]
use libfuzzer_sys::fuzz_target;

use tezos_conversation::{Tree, PacketDescriptor, simulate_handshake};

fuzz_target!(|data: &[u8]| {
    let mut output = Tree::default();

    let descriptors = [
        PacketDescriptor::new(60, false).unwrap(),
        PacketDescriptor::new(60, true).unwrap(),
    ];
    simulate_handshake(descriptors.as_ref(), data.as_ref(), &mut output);
});
