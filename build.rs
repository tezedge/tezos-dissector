extern crate bindgen;
extern crate cmake;

use std::{
    process::Command,
    path::Path,
};

#[allow(dead_code)]
fn prepare_sources() {
    let _ = Command::new("git")
        .args(&["clone", "https://code.wireshark.org/review/wireshark"])
        .output().map(|_| ()).or_else(|_| Ok::<_, ()>(()));
    let _ = Command::new("git")
        .current_dir("wireshark")
        .args(&["reset", "--hard", "0cce968634b30145ab9670f4855dd718128578e4"])
        .status().unwrap();
}

fn generate_bindings<Q>(header: &str, rust_module: Q)
where
    Q: AsRef<Path>,
{
    use std::{str, fs};

    let dependency_time = fs::metadata(header).ok()
        .and_then(|s| s.modified().ok())
        .unwrap_or_else(|| panic!("dependency: {:?} not found", header));
    let modified = fs::metadata(&rust_module).ok().and_then(|s| s.modified().ok())
        .map(|target_time| dependency_time > target_time)
        .unwrap_or(true);

    if !modified {
        return
    }

    let output = Command::new("pkg-config")
        .args(&["--cflags", "glib-2.0"])
        .output().unwrap();
    let glib_includes = str::from_utf8(output.stdout.as_slice()).unwrap().trim_end_matches('\n');
    let bindings = bindgen::Builder::default()
        .header(header)
        .clang_arg("-I./wireshark")
        .clang_args(glib_includes.split(' '))
        .generate()
        .expect("Unable to generate bindings");
    bindings
        .write_to_file(&rust_module)
        .unwrap_or_else(|e| panic!("Unable to save bindings: {}", e));
}

fn main() {
    println!("cargo:rerun-if-changed=wireshark");

    generate_bindings("wireshark/epan/packet.h", "src/ffi/packet.rs");
    generate_bindings("wireshark/epan/proto.h", "src/ffi/proto.rs");
    generate_bindings("wireshark/epan/ftypes/ftypes.h", "src/ffi/ftypes.rs");

    let out = cmake::build("wireshark");
    println!("cargo:rustc-env=WIRESHARK={}", out.display());
}
