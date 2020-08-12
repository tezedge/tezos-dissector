fn main() {
    use std::{os::unix::fs::symlink, process::Command, fs::remove_file};

    let _ = Command::new("git")
        .args(&["clone", "https://code.wireshark.org/review/wireshark"])
        .output()
        .map(|_| ())
        .or_else(|_| Ok::<_, ()>(()));
    let _ = Command::new("git")
        .current_dir("wireshark")
        .args(&["reset", "--hard", "ed20ddea8138"])
        .status()
        .unwrap();

    let out = cmake::build("wireshark");
    let _ = remove_file("target/out");
    symlink(&out, "target/out").unwrap();
    println!("cargo:rustc-env=WIRESHARK={}", out.display());
    println!("cargo:rustc-env=SODIUM_SHARED=1");
    println!("cargo:rustc-env=SODIUM_USE_PKG_CONFIG=1");
}
