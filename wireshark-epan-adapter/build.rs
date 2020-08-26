use std::{process::Command, str, env, path::PathBuf};

fn main() {
    // will use well known path of headers,
    // can be override by env variable `WIRESHARK_EPAN_HEADERS`
    let epan_include =
        env::var("WIRESHARK_EPAN_HEADERS").unwrap_or("/usr/include/wireshark/epan".to_owned());

    // if the wireshark updates, this script will rerun in order to generate fresh bindings
    // backward compatibility is the responsibility of the wireshark team
    println!("cargo:rerun-if-changed={}", epan_include);

    // use pkg-config to determine where are glib headers
    let output = Command::new("pkg-config")
        .args(&["--cflags", "glib-2.0"])
        .output()
        .unwrap();
    let glib_includes = str::from_utf8(output.stdout.as_slice())
        .unwrap()
        .trim_end_matches('\n');

    // configure the builder
    let bindings = bindgen::Builder::default()
        .header(format!("{}/ftypes/ftypes.h", epan_include))
        .header(format!("{}/proto.h", epan_include))
        .header(format!("{}/packet.h", epan_include))
        .header(format!("{}/conversation.h", epan_include))
        .header(format!("{}/tvbuff.h", epan_include))
        .header(format!("{}/tvbuff-int.h", epan_include))
        .header(format!("{}/dissectors/packet-tcp.h", epan_include))
        .header(format!("{}/wmem/wmem_user_cb.h", epan_include))
        .header(format!("{}/prefs.h", epan_include))
        .clang_args(&["-I/usr/include/wireshark", "-DHAVE_PLUGINS"])
        .clang_args(glib_includes.split(' '))
        .generate()
        .expect("Unable to generate bindings");

    // create the binding in `OUT_DIR`
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs.raw"))
        .expect("Couldn't write bindings!");
}
