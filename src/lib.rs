#[rustfmt::skip]
#[allow(non_upper_case_globals, non_camel_case_types, non_snake_case, dead_code)]
mod ffi;

pub mod glue;

#[cfg(test)]
#[test]
fn dir() {
    println!("{}", env!("WIRESHARK"));
}
