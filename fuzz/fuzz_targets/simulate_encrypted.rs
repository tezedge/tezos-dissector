#![no_main]
use libfuzzer_sys::fuzz_target;

use tezos_conversation::{Tree, PacketDescriptor, ChunkDescriptor, simulate_encrypted};

fuzz_target!(|data: &[u8]| {
    let mut output = Tree::default().panic_on_decryption_error();

    let chunk_oversize = 18;
    let descriptors = [
        PacketDescriptor::new(chunk_oversize + 15, false).unwrap(),
        PacketDescriptor::new(chunk_oversize + 12, true).unwrap(),
        PacketDescriptor::new(chunk_oversize + 25, false).unwrap(),
        PacketDescriptor::new(chunk_oversize + 18, true).unwrap(),
    ];
    let ic = [
        ChunkDescriptor::new(13).unwrap(),
        ChunkDescriptor::new(12).unwrap(),
        ChunkDescriptor::new(15).unwrap(),
    ];
    let rc = [
        ChunkDescriptor::new(8).unwrap(),
        ChunkDescriptor::new(12).unwrap(),
        ChunkDescriptor::new(10).unwrap(),
    ];
    simulate_encrypted(descriptors.as_ref(), ic.as_ref(), rc.as_ref(), data.as_ref(), &mut output);
});
