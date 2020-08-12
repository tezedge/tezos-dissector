// copy the library into plugin directory
// cp target/debug/libtezos_dissector.so target/out/lib/wireshark/plugins/3.3/epan/

#[rustfmt::skip]
#[allow(non_upper_case_globals, non_camel_case_types, non_snake_case, dead_code)]
mod wireshark;

mod core;

mod conversation;

#[cfg(test)]
#[test]
fn dir() {
    println!("{}", env!("WIRESHARK"));
}
