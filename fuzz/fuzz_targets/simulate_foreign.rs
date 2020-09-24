#![no_main]
use libfuzzer_sys::fuzz_target;

use tezos_conversation::{Tree, PacketDescriptor, simulate_foreign};

fuzz_target!(|data: &[u8]| {
    let mut output = Tree::default();

    let descriptors = [
        PacketDescriptor::new(15, false).unwrap(),
        PacketDescriptor::new(15, true).unwrap(),
        PacketDescriptor::new(16, false).unwrap(),
        PacketDescriptor::new(16, true).unwrap(),
    ];
    simulate_foreign(descriptors.as_ref(), data.as_ref(), &mut output);
});
