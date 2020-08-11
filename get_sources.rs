#!/usr/bin/env run-cargo-script

// to be able to run it:
// $ cargo install cargo-script

use std::process::Command;

fn main() {
    let _ = Command::new("git")
        .args(&["clone", "https://code.wireshark.org/review/wireshark"])
        .output().map(|_| ()).or_else(|_| Ok::<_, ()>(()));
    let _ = Command::new("git")
        .current_dir("wireshark")
        .args(&["reset", "--hard", "0cce968634b30145ab9670f4855dd718128578e4"])
        .status().unwrap();
}
