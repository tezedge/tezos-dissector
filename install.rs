#!/usr/bin/env run-cargo-script

// to be able to run it:
// $ cargo install cargo-script

fn main() {
    use std::{env, fs, path::PathBuf};

    let usage_msg = "usage: ./install.rs debug|release [optional path]";

    let debug = match env::args().nth(1) {
        Some(s) if s == "debug" => true,
        Some(s) if s == "release" => false,
        _ => panic!("{}", usage_msg),
    };

    let source = if debug {
        "target/debug/libtezos_dissector.so"
    } else {
        "target/release/libtezos_dissector.so"
    };

    let home = format!("{}/.local", std::env::var("HOME").unwrap());
    let system = "/usr".to_owned();
    let local = "target/out".to_owned();

    let destination = if debug {
        local
    } else {
        system
    };

    let destination = format!("{}/lib/wireshark/plugins/3.2/epan/", destination)
        .parse::<PathBuf>()
        .expect("valid path");

    fs::create_dir_all(&destination).unwrap();
    let _ = fs::copy(source, destination.join("libtezos_dissector.so")).unwrap();
}
