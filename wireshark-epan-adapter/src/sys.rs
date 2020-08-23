#![allow(non_upper_case_globals, non_camel_case_types, non_snake_case, dead_code)]
#![allow(improper_ctypes)] // WARNING: remove this line when llvm and rust fixed u128 ffi
include!(concat!(env!("OUT_DIR"), "/bindings.rs.raw"));
