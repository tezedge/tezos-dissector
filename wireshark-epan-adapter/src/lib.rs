/// Bindings generated automatically.
mod sys;

/// Covers plugin, protocol and dissector registering.
mod plugin;
pub use self::plugin::{Plugin, NameDescriptor, PrefFilenameDescriptor, DissectorDescriptor, Dissector};

/// Wrappers around stuff that passed inside the dissector.
mod dissector;
pub use self::dissector::Tree;

pub const PLUGIN_WANT_MAJOR: i32 = sys::WIRESHARK_VERSION_MAJOR as i32;

pub const PLUGIN_WANT_MINOR: i32 = sys::WIRESHARK_VERSION_MINOR as i32;
