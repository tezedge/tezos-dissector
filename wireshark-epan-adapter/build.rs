use std::{process::Command, str, env, path::PathBuf};

fn main() {
    // use pkg-config to determine where are wireshark and glib headers
    let output = Command::new("pkg-config")
        .args(&["--cflags", "wireshark"])
        .output()
        .expect("wireshark installed and accessible via pkg-config");
    let includes = str::from_utf8(output.stdout.as_slice())
        .unwrap()
        .trim_end_matches('\n');

    let base = includes
        .split(' ')
        .find(|s| s.starts_with("-I") && s.ends_with("include/wireshark"))
        .expect("wireshark installed and accessible via pkg-config")
        .trim_start_matches("-I");
    println!("base: {}", base);

    // if the wireshark updates, this script will rerun in order to generate fresh bindings
    // backward compatibility is the responsibility of the wireshark team
    println!("cargo:rerun-if-changed={}", base);

    // configure the builder
    let builder = bindgen::Builder::default()
        .clang_args(includes.split(' '))
        .clang_arg("-DHAVE_PLUGINS")
        .header(format!("{}/epan/ftypes/ftypes.h", base))
        .header(format!("{}/epan/proto.h", base))
        .header(format!("{}/epan/packet.h", base))
        .header(format!("{}/epan/conversation.h", base))
        .header(format!("{}/epan/tvbuff.h", base))
        .header(format!("{}/epan/tvbuff-int.h", base))
        .header(format!("{}/epan/dissectors/packet-tcp.h", base))
        .header(format!("{}/epan/wmem/wmem_user_cb.h", base))
        .header(format!("{}/epan/prefs.h", base));

    // on archlinux ws_version.h is present, on ubuntu it is not, but there is config.h
    // https://bugs.archlinux.org/task/63828#comments
    // here explained that config.h is not intended to be public, so we will use ws_version.h
    // and simulate ws_version.h if needed
    let ws_version = format!("{}/ws_version.h", base);
    let builder = if PathBuf::from(&ws_version).exists() {
        builder.header(ws_version)
    } else {
        builder
            .header(format!("{}/config.h", base))
            .header("ws_version.h")
    };

    let bindings = builder.generate().expect("Unable to generate bindings");

    // create the binding in `OUT_DIR`
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs.raw"))
        .expect("Couldn't write bindings!");
}
