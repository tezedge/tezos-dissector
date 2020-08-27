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
