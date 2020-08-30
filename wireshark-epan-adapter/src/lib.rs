/// Bindings generated automatically.
mod sys;

/// Covers plugin, protocol and dissector registering.
mod plugin;
pub use self::plugin::{
    Plugin, NameDescriptor, FieldDescriptor, FieldDescriptorOwned, PrefFilenameDescriptor,
    DissectorDescriptor, Dissector,
};

/// Wrappers around stuff that passed inside the dissector.
pub mod dissector;

#[no_mangle]
pub static plugin_want_major: i32 = sys::VERSION_MAJOR as i32;

#[no_mangle]
pub static plugin_want_minor: i32 = sys::VERSION_MINOR as i32;
