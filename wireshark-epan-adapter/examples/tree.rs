#[rustfmt::skip]
use wireshark_epan_adapter::{
    Plugin, NameDescriptor, FieldDescriptor,
    DissectorDescriptor,
    Dissector,
    dissector::DissectorHelper,
};

#[no_mangle]
static plugin_version: &str = concat!(env!("CARGO_PKG_VERSION"), "\0");

#[no_mangle]
static plugin_want_major: i32 = 3;

#[no_mangle]
static plugin_want_minor: i32 = 2;

#[no_mangle]
extern "C" fn plugin_register() {
    Plugin::new::<usize>(NameDescriptor {
        name: "Simple Protocol\0",
        short_name: "simple_protocol\0",
        filter_name: "simple_tree_example\0",
    })
    .add_field(FieldDescriptor::String {
        name: "Foo\0",
        abbrev: "simple_tree_example.foo\0",
    })
    .add_field(FieldDescriptor::String {
        name: "Foo Bar0\0",
        abbrev: "simple_tree_example.foo.bar0\0",
    })
    .add_field(FieldDescriptor::String {
        name: "Foo Bar1\0",
        abbrev: "simple_tree_example.foo.bar1\0",
    })
    .add_field(FieldDescriptor::String {
        name: "Foo Bar0 Baz0\0",
        abbrev: "simple_tree_example.foo.bar0.baz0\0",
    })
    .add_field(FieldDescriptor::String {
        name: "Foo Bar0 Baz1\0",
        abbrev: "simple_tree_example.foo.bar0.baz1\0",
    })
    .set_ett_number(1)
    .set_dissector(DissectorDescriptor {
        display_name: "Simple\0",
        short_name: "simple_tcp\0",
        dissector: Box::new(SimpleDissector),
    })
    .register()
}

struct SimpleDissector;

impl Dissector for SimpleDissector {
    fn consume(&mut self, helper: &mut DissectorHelper) -> usize {
        use wireshark_epan_adapter::dissector::DissectorTreeLeaf::{Nothing, String};

        let payload = helper.payload();
        let length = payload.len();
        let root = helper.root();

        let mut main_node = root
            .leaf("simple_tree_example\0", 0..length, Nothing)
            .subtree();
        if length > 100 {
            let mut foo_node = main_node
                .leaf(
                    "simple_tree_example.foo\0",
                    0..length,
                    String("foo data".to_owned()),
                )
                .subtree();
            let mut bar0_node = foo_node
                .leaf(
                    "simple_tree_example.foo.bar0\0",
                    0..100,
                    String("bar0 data".to_owned()),
                )
                .subtree();
            bar0_node.leaf(
                "simple_tree_example.foo.bar0.baz0\0",
                0..20,
                String("baz0 data".to_owned()),
            );
            bar0_node.leaf(
                "simple_tree_example.foo.bar0.baz1\0",
                20..100,
                String("baz1 data".to_owned()),
            );
            foo_node.leaf(
                "simple_tree_example.foo.bar1\0",
                100..length,
                String("bar1 data".to_owned()),
            );
        }

        length
    }
}
