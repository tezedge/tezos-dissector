// Copyright (c) SimpleStaking and Tezedge Contributors
// SPDX-License-Identifier: MIT

use std::{os::unix::fs::symlink, process::Command, fs::remove_file};

fn main() {
    if !cfg!(debug_assertions) {
        return;
    };

    let _ = Command::new("git")
        .args(&["clone", "https://code.wireshark.org/review/wireshark"])
        .output()
        .map(|_| ())
        .or_else(|_| Ok::<_, ()>(()));
    let _ = Command::new("git")
        .current_dir("wireshark")
        .args(&["reset", "--hard", "4f9257fb8ccc"])
        .status()
        .unwrap();

    let out = cmake::build("wireshark");
    let _ = remove_file("target/out");
    symlink(&out, "target/out").unwrap();
    println!("cargo:rustc-env=WIRESHARK={}", out.display());
}
