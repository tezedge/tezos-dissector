use structopt::StructOpt;
use os_type::{current_platform, OSType};
use std::{process::{Command, Stdio}, str::from_utf8, env, path::{PathBuf, Path}, fs, io};

#[derive(StructOpt)]
struct Params {
    #[structopt(short = "d")]
    use_docker: bool,
}

fn build_in_docker<T, P>(tag: T, output: &P)
where
    T: AsRef<str>,
    P: AsRef<Path>,
{
    let mut build = Command::new("docker")
        .args(&["build", "-t"])
        .arg(format!("wireshark-plugin-builder:{}", tag.as_ref()))
        .arg("-f")
        .arg(format!("prebuilt/wpb.{}.dockerfile", tag.as_ref()))
        .arg(".")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    build.wait().unwrap();
    let create = Command::new("docker")
        .arg("create")
        .arg(format!("wireshark-plugin-builder:{}", tag.as_ref()))
        .output()
        .unwrap();
    let cid = from_utf8(create.stdout.as_ref()).unwrap();
    let cid = cid.trim_end_matches('\n');
    Command::new("docker")
        .arg("cp")
        .arg(format!("{}:/usr/local/tezos-dissector/target/release/libtezos_dissector.so", cid))
        .arg(output.as_ref())
        .output()
        .unwrap();
    Command::new("docker")
        .arg("rm")
        .arg(cid)
        .output()
        .unwrap();
}

fn get_wireshark_version() -> (u32, u32) {
    let output = Command::new("wireshark")
        .arg("-v")
        .output()
        .expect("Wireshark installed?");
    let mut version_lines = from_utf8(output.stdout.as_ref()).unwrap().lines();
    let mut version_words = version_lines.next().unwrap().split_whitespace();
    let name = version_words.next().unwrap();
    assert_eq!(name, "Wireshark");
    let triple = version_words.next().unwrap().split('.').collect::<Vec<_>>();
    let major = triple[0].parse::<u32>().unwrap();
    let minor = triple[1].parse::<u32>().unwrap();
    (major, minor)
}

fn main() {
    let params = Params::from_args();

    let (major, minor) = get_wireshark_version();

    let platform = current_platform();
    match platform.os_type {
        OSType::Ubuntu | OSType::Manjaro => {
            let plugin_path = format!(
                "{}/.local/lib/wireshark/plugins/{}.{}/epan/",
                env::var("HOME").unwrap(),
                major,
                minor,
            );
            let plugin_path = plugin_path.parse::<PathBuf>().unwrap();
            fs::create_dir_all(plugin_path.clone()).unwrap();

            if params.use_docker {
                let tag = match (major, minor) {
                    (3, 0) => "ubuntu-19.10",
                    (3, 2) => "ubuntu-20.04",
                    _ => panic!("Not yet supported Wireshark"),
                };
                build_in_docker(&tag, &plugin_path);
            } else {
                let path = format!("prebuilt/libtezos_dissector_linux_{}_{}.so", major, minor);
                let path = path.parse::<PathBuf>().unwrap();
                fs::copy(path, plugin_path.join("libtezos_dissector.so"))
                    .unwrap_or_else(|e| match e.kind() {
                        io::ErrorKind::NotFound => panic!(
                            "there is no prebuilt plugin for your platform and Wireshark {}.{}",
                            major,
                            minor,
                        ),
                        _ => panic!(e),
                    });
            }
        },
        OSType::OSX => {
            let path = format!("prebuilt/libtezos_dissector_macos_{}_{}.dylib", major, minor);
            let path = path.parse::<PathBuf>().unwrap();
            let plugin_path = format!(
                "/Applications/Wireshark.app/Contents/PlugIns/wireshark/{}-{}/epan",
                major,
                minor,
            );
            let plugin_path = plugin_path.parse::<PathBuf>().unwrap();
            fs::copy(path, plugin_path.join("libtezos_dissector.so"))
                .unwrap_or_else(|e| match e.kind() {
                    io::ErrorKind::NotFound => panic!(
                        "there is no prebuilt plugin for your platform and Wireshark {}.{}",
                        major,
                        minor,
                    ),
                    _ => panic!(e),
                });
        },
        _ => panic!("Not yet supported platform"),
    }
}
