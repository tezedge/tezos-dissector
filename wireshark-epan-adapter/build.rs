fn main() {
    use std::{process::Command, str, env};

    println!("cargo:rerun-if-changed=/usr/include/wireshark/epan");

    let output = Command::new("pkg-config")
        .args(&["--cflags", "glib-2.0"])
        .output()
        .unwrap();
    let glib_includes = str::from_utf8(output.stdout.as_slice())
        .unwrap()
        .trim_end_matches('\n');

    let wpan_include =
        env::var("WIRESHARK_EPAN_HEADERS").unwrap_or("/usr/include/wireshark/epan".to_owned());

    let bindings = bindgen::Builder::default()
        .header(format!("{}/ftypes/ftypes.h", wpan_include))
        .header(format!("{}/proto.h", wpan_include))
        .header(format!("{}/packet.h", wpan_include))
        .header(format!("{}/conversation.h", wpan_include))
        .header(format!("{}/tvbuff.h", wpan_include))
        .header(format!("{}/tvbuff-int.h", wpan_include))
        .header(format!("{}/dissectors/packet-tcp.h", wpan_include))
        .header(format!("{}/wmem/wmem_user_cb.h", wpan_include))
        .header(format!("{}/prefs.h", wpan_include))
        .clang_args(&["-I/usr/include/wireshark", "-DHAVE_PLUGINS"])
        .clang_args(glib_includes.split(' '))
        .generate()
        .expect("Unable to generate bindings");
    bindings
        .write_to_file("src/sys.rs")
        .unwrap_or_else(|e| panic!("Unable to save bindings: {}", e));
}
