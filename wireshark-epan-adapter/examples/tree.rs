// Minimal example, builds tree.

use wireshark_definitions::{FieldDescriptor, TreePresenter};

#[rustfmt::skip]
use wireshark_epan_adapter::{
    Plugin, NameDescriptor, DissectorDescriptor, Dissector,
    dissector::{Packet, Tree, PacketInfo},
};

// Version of this plugin.
#[no_mangle]
static plugin_version: &str = concat!(env!("CARGO_PKG_VERSION"), "\0");

// Major version of required wireshark.
#[no_mangle]
static plugin_want_major: i32 = wireshark_epan_adapter::PLUGIN_WANT_MAJOR;

// Minor version of required wireshark.
#[no_mangle]
static plugin_want_minor: i32 = wireshark_epan_adapter::PLUGIN_WANT_MINOR;

// Function that register the plugin.
#[no_mangle]
extern "C" fn plugin_register() {
    // plugin can be constant
    const PLUGIN: Plugin<'static> = Plugin::new(
        // short and full name of dissector
        DissectorDescriptor {
            display_name: "Simple\0",
            short_name: "simple_tcp\0",
        },
        // name of protocol and filter
        NameDescriptor {
            name: "Simple Protocol\0",
            short_name: "simple_protocol\0",
            filter_name: "simple_tree_example\0",
        },
        // all branches of any tree should be known statically
        &[&[
            FieldDescriptor::String {
                name: "Foo\0",
                abbrev: "simple_tree_example.foo\0",
            },
            FieldDescriptor::String {
                name: "Foo Bar0\0",
                abbrev: "simple_tree_example.foo.bar0\0",
            },
            FieldDescriptor::String {
                name: "Foo Bar1\0",
                abbrev: "simple_tree_example.foo.bar1\0",
            },
            FieldDescriptor::String {
                name: "Foo Bar0 Baz0\0",
                abbrev: "simple_tree_example.foo.bar0.baz0\0",
            },
            FieldDescriptor::String {
                name: "Foo Bar0 Baz1\0",
                abbrev: "simple_tree_example.foo.bar0.baz1\0",
            },
        ]],
        &[],
    );

    // register the plugin and the dissector object
    PLUGIN.register(Box::new(SimpleDissector))
}

// The dissector can contain some state, but in this example it does not.
struct SimpleDissector;

// The trait `Dissector` should be implemented for the dissector.
impl Dissector for SimpleDissector {
    // This method called by the wireshark when a new packet just arrive,
    // or when the user click on the packet.
    // Perform dissection and prepare the tree interface inside this method.
    fn consume(
        // it is possible to modify the state of the dissector
        &mut self,
        // API for constructing the tree interface
        root: &mut Tree,
        // provides the the payload
        packet: &Packet,
        // provides the packet id, payload, source and destination of the packet
        _packet_info: &PacketInfo,
    ) -> usize {
        use wireshark_definitions::TreeLeaf;

        let payload = packet.payload();
        let length = payload.len();

        // creates a root node in the tree
        let mut main_node = root
            .add("simple_tree_example", 0..length, TreeLeaf::nothing())
            .subtree();

        // let's add subtrees at each packet bigger than 100 bytes
        if length > 100 {
            // highlight 0..length bytes in this branch
            let mut foo_node = main_node
                .add("foo", 0..length, TreeLeaf::Display("foo data"))
                .subtree();
            // highlight 0..100 bytes in this subbranch
            let mut bar0_node = foo_node
                .add("bar0", 0..100, TreeLeaf::Display("bar0 data"))
                .subtree();
            bar0_node.add("baz0", 0..20, TreeLeaf::Display("baz0 data"));
            bar0_node.add("baz1", 20..100, TreeLeaf::Display("baz1 data"));
            foo_node.add("bar1", 100..length, TreeLeaf::Display("bar1 data"));
        }

        // return consumed length, if return 0 and do not add branches to tree,
        // the wireshark consider this packet is not belong to this dissector
        length
    }

    // This method called by the wireshark when the user
    // closing current capturing session
    fn cleanup(&mut self) {}
}

impl Drop for SimpleDissector {
    fn drop(&mut self) {
        log::info!("drop");
    }
}
