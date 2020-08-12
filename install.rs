#!/usr/bin/env run-cargo-script

// to be able to run it:
// $ cargo install cargo-script

fn main() {
    use std::{env, fs, path::PathBuf};

    let usage_msg = "usage: ./install.rs debug|release [optional path]";

    let source = match env::args().nth(1) {
        Some(s) if s == "debug" => "target/debug/libtezos_dissector.so",
        Some(s) if s == "release" => "target/release/libtezos_dissector.so",
        _ => panic!("{}", usage_msg),
    };

    let destination = env::args()
        .nth(2)
        .unwrap_or("~/.local/lib/wireshark/plugins/3.2/epan/".to_owned())
        .replace('~', std::env::var("HOME").unwrap().as_str())
        .parse::<PathBuf>()
        .expect("valid path");

    fs::create_dir_all(&destination).unwrap();
    let _ = fs::copy(source, destination.join("libtezos_dissector.so")).unwrap();
}
