extern crate bindgen;

use std::process::Command;

fn main() {
    use std::{
        str,
        os::unix::fs::symlink,
        fs::remove_file,
    };

    println!("cargo:rerun-if-changed=out");

    let output = Command::new("pkg-config")
        .args(&["--cflags", "glib-2.0"])
        .output().unwrap();
    let glib_includes = str::from_utf8(output.stdout.as_slice()).unwrap().trim_end_matches('\n');

    let bindings = bindgen::Builder::default()
        .header("wireshark/epan/ftypes/ftypes.h")
        .header("wireshark/epan/proto.h")
        .header("wireshark/epan/packet.h")
        .header("wireshark/epan/conversation.h")
        .header("wireshark/epan/dissectors/packet-tcp.h")
        .header("wireshark/epan/wmem/wmem_user_cb.h")
        .header("wireshark/epan/prefs.h")
        .clang_args(&["-I./wireshark", "-DHAVE_PLUGINS"])
        .clang_args(glib_includes.split(' '))
        .generate()
        .expect("Unable to generate bindings");
    bindings
        .write_to_file("src/wireshark.rs")
        .unwrap_or_else(|e| panic!("Unable to save bindings: {}", e));

    let out = cmake::build("wireshark");
    let _ = remove_file("target/out");
    symlink(&out, "target/out").unwrap();
    println!("cargo:rustc-env=WIRESHARK={}", out.display());
    println!("cargo:rustc-env=SODIUM_SHARED=1");
    println!("cargo:rustc-env=SODIUM_USE_PKG_CONFIG=1");
}
