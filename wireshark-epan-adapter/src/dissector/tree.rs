use std::{collections::BTreeMap, ops::Range};
use crate::sys;

pub struct DissectorSubtree(*mut sys::proto_tree);

pub struct DissectorTree {
    proto_handle: i32,
    fields: BTreeMap<&'static str, i32>,
    ett: Vec<i32>,
    tvb: *mut sys::tvbuff_t,
    tree: *mut sys::proto_tree,
}

impl DissectorTree {
    pub(crate) fn new(
        proto_handle: i32,
        fields: BTreeMap<&'static str, i32>,
        ett: Vec<i32>,
        tvb: *mut sys::tvbuff_t,
        tree: *mut sys::proto_tree,
    ) -> Self {
        DissectorTree {
            proto_handle,
            fields,
            tvb,
            ett,
            tree,
        }
    }

    pub fn subtree(&mut self, index: usize, range: Range<usize>) -> DissectorSubtree {
        unsafe {
            let ti = sys::proto_tree_add_item(
                self.tree,
                self.proto_handle,
                self.tvb,
                range.start as _,
                range.len() as _,
                sys::ENC_NA,
            );
            DissectorSubtree(sys::proto_item_add_subtree(ti, self.ett[index]))
        }
    }

    pub fn add_string_field(
        &mut self,
        subtree: &DissectorSubtree,
        field_abbrev: &'static str,
        value: String,
        range: Range<usize>,
    ) {
        let mut value = value;
        value.push('\0');
        unsafe {
            sys::proto_tree_add_string(
                subtree.0,
                self.fields[field_abbrev],
                self.tvb,
                range.start as _,
                range.len() as _,
                value.as_ptr() as _,
            );
        }
    }

    pub fn add_int_field(
        &mut self,
        subtree: &DissectorSubtree,
        field_abbrev: &'static str,
        value: i64,
        range: Range<usize>,
    ) {
        unsafe {
            sys::proto_tree_add_int64(
                subtree.0,
                self.fields[field_abbrev],
                self.tvb,
                range.start as _,
                range.len() as _,
                value,
            );
        }
    }
}
