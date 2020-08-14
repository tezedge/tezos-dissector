use std::{collections::BTreeMap, ptr};
use crate::sys;

pub struct DissectorTree {
    proto_handle: i32,
    fields: BTreeMap<&'static str, i32>,
    ett: Vec<i32>,
    tvb: *mut sys::tvbuff_t,
    tree: *mut sys::proto_tree,
    subtrees: Vec<*mut sys::proto_tree>,
}

impl DissectorTree {
    pub(crate) fn new(
        proto_handle: i32,
        fields: BTreeMap<&'static str, i32>,
        ett: Vec<i32>,
        tvb: *mut sys::tvbuff_t,
        tree: *mut sys::proto_tree,
    ) -> Self {
        let subtrees = ett.iter().map(|_| ptr::null_mut()).collect();
        DissectorTree {
            proto_handle,
            fields,
            tvb,
            ett,
            tree,
            subtrees,
        }
    }

    // lazy
    fn subtree(&mut self, index: usize) -> Option<*mut sys::proto_tree> {
        if index < self.subtrees.len() {
            Some(unsafe {
                if self.subtrees[index].is_null() {
                    let ti = sys::proto_tree_add_item(
                        self.tree,
                        self.proto_handle,
                        self.tvb,
                        0,
                        -1,
                        sys::ENC_NA,
                    );
                    self.subtrees[index] = sys::proto_item_add_subtree(ti, self.ett[index]);
                }
                self.subtrees[index]
            })
        } else {
            None
        }
    }

    pub fn add_string_field(&mut self, index: usize, field_abbrev: &'static str, value: String) {
        use std::os::raw::{c_char, c_int};

        if let Some(subtree) = self.subtree(index) {
            unsafe {
                sys::proto_tree_add_string_format_value(
                    subtree,
                    self.fields[field_abbrev],
                    self.tvb,
                    0,
                    0,
                    value.as_ptr() as _,
                    b"%.*s\0".as_ptr() as _,
                    (value.len() + 1) as c_int,
                    value.as_ptr() as *const c_char,
                );
            }
        }
    }
}
