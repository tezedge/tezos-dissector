extern crate wireshark_epan_adapter;
extern crate os_type;

use wireshark_epan_adapter::{plugin_want_major, plugin_want_minor};
use os_type::{current_platform, OSType};
use std::{fs, env, path::PathBuf, ffi::OsStr};

fn read_target_dir(debug: bool, extension: &str) -> PathBuf {
    let path = if debug { "target/debug" } else { "target/release" };
    fs::read_dir(path)
        .expect("should build plugin")
        .filter_map(|d| {
            d.as_ref()
                .ok()
                .and_then(|d| {
                    let path = d.path();
                    if path.extension() == Some(OsStr::new(extension)) {
                        Some(path)
                    } else {
                        None
                    }
                })
        })
        .next()
        .unwrap_or_else(|| panic!("should contain *.{} file", extension))
}

fn main() {
    let platform = current_platform();
    match platform.os_type {
        OSType::Ubuntu | OSType::Manjaro => {
            let wireshark_version = format!("{}.{}", plugin_want_major, plugin_want_minor);
            let plugin_path = format!(
                "{}/.local/lib/wireshark/plugins/{}/epan/",
                env::var("HOME").unwrap(),
                wireshark_version,
            );
            let plugin_path = plugin_path.parse::<PathBuf>().unwrap();
            let path = read_target_dir(false, "so");
            fs::copy(path.clone(), plugin_path.join(path.file_name().unwrap())).unwrap();
        },
        OSType::OSX => {
            let wireshark_version = format!("{}-{}", plugin_want_major, plugin_want_minor);
            let plugin_path = format!(
                "/Applications/Wireshark.app/Contents/PlugIns/wireshark/{}/epan",
                wireshark_version,
            );
            let plugin_path = plugin_path.parse::<PathBuf>().unwrap();
            let path = read_target_dir(false, "dylib");
            let name = format!("{}.so", path.file_stem().unwrap().to_str().unwrap());
            fs::copy(path, plugin_path.join(name)).unwrap();
        },
        _ => panic!("Not yet supported platform"),
    }
}
