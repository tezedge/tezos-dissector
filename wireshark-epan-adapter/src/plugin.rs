use std::{
    collections::BTreeMap,
    os::raw::{c_int, c_char, c_void},
    ptr,
};
use super::sys;

pub struct DissectorInfo<'a> {
    pub tvb: &'a mut sys::tvbuff_t,
    pub pinfo: &'a mut sys::packet_info,
    pub tree: &'a mut sys::proto_tree,
    pub mark: usize,
    pub fields: BTreeMap<&'a str, i32>,
    pub ett: Vec<i32>,
}

pub trait Dissector {
    fn recognize(&self, info: DissectorInfo<'_>) -> bool;
    fn consume(&mut self, info: DissectorInfo<'_>) -> usize;
}

struct EpanPluginPrivates<'a> {
    plugin: sys::proto_plugin,
    proto_handle: i32,
    hf: Vec<sys::hf_register_info>,
    ett: Vec<&'a mut c_int>,
    pref_filenames: Vec<*const c_char>,
    dissector_handle: sys::dissector_handle_t,
}

impl<'a> EpanPluginPrivates<'a> {
    pub fn empty() -> Self {
        EpanPluginPrivates {
            plugin: sys::proto_plugin {
                register_protoinfo: None,
                register_handoff: None,
            },
            proto_handle: -1,
            hf: Vec::new(),
            ett: Vec::new(),
            pref_filenames: Vec::new(),
            dissector_handle: ptr::null_mut(),
        }
    }
}

pub struct EpanPlugin<'a> {
    privates: EpanPluginPrivates<'a>,
    name_descriptor: EpanNameDescriptor<'a>,
    field_descriptors: Vec<(i32, EpanFieldDescriptor<'a>)>,
    ett: Vec<i32>,
    pref_descriptor: Option<EpanPrefDescriptor<'a>>,
    dissector_descriptor: Option<EpanDissectorDescriptor<'a>>,
}

pub struct EpanNameDescriptor<'a> {
    pub name: &'a str,
    pub short_name: &'a str,
    pub filter_name: &'a str,
}

pub enum EpanFieldDescriptor<'a> {
    String { name: &'a str, abbrev: &'a str },
    Int64Dec { name: &'a str, abbrev: &'a str },
}

impl<'a> EpanFieldDescriptor<'a> {
    pub fn abbrev(&self) -> &'a str {
        match self {
            &EpanFieldDescriptor::String {
                name: _,
                abbrev: ref abbrev,
            } => abbrev.clone(),
            &EpanFieldDescriptor::Int64Dec {
                name: _,
                abbrev: ref abbrev,
            } => abbrev.clone(),
        }
    }
}

pub struct EpanPrefDescriptor<'a> {
    pub callback: Box<dyn FnMut(Vec<&'a str>)>,
    pub filename_fields: Vec<EpanPrefFilenameDescriptor<'a>>,
    // add more
    // `pub string_fields: Vec<EpanPrefStringDescriptor<'a>>,`
}

pub struct EpanPrefFilenameDescriptor<'a> {
    pub name: &'a str,
    pub title: &'a str,
    pub description: &'a str,
}

pub struct EpanDissectorDescriptor<'a> {
    pub name: &'a str,
    pub display_name: &'a str,
    pub short_name: &'a str,
    pub dissector: Box<dyn Dissector>,
}

impl<'a> EpanPlugin<'a> {
    pub fn new(name_descriptor: EpanNameDescriptor<'a>) -> Self {
        EpanPlugin {
            privates: EpanPluginPrivates::empty(),
            name_descriptor: name_descriptor,
            field_descriptors: Vec::new(),
            ett: Vec::new(),
            pref_descriptor: None,
            dissector_descriptor: None,
        }
    }

    pub fn add_field(self, field_descriptor: EpanFieldDescriptor<'a>) -> Self {
        let mut s = self;
        s.field_descriptors.push((-1, field_descriptor));
        s
    }

    pub fn set_ett_number(self, number: usize) -> Self {
        let mut s = self;
        s.ett.resize(number, -1);
        s
    }

    pub fn set_pref(self, pref_descriptor: EpanPrefDescriptor<'a>) -> Self {
        let mut s = self;
        s.pref_descriptor = Some(pref_descriptor);
        s
    }

    pub fn set_dissector(self, dissector_descriptor: EpanDissectorDescriptor<'a>) -> Self {
        let mut s = self;
        s.dissector_descriptor = Some(dissector_descriptor);
        s
    }

    fn fields(&self) -> BTreeMap<&'a str, i32> {
        self.field_descriptors
            .iter()
            .map(|(field, descriptor)| (descriptor.abbrev(), field.clone()))
            .collect()
    }
}

impl EpanPlugin<'static> {
    pub fn register(self) {
        static mut CONTEXT: Option<EpanPlugin<'static>> = None;

        unsafe fn context() -> &'static EpanPlugin<'static> {
            CONTEXT.as_ref().unwrap()
        }

        unsafe fn context_mut() -> &'static mut EpanPlugin<'static> {
            CONTEXT.as_mut().unwrap()
        }

        unsafe extern "C" fn register_protoinfo() {
            let proto = sys::proto_register_protocol(
                context().name_descriptor.name.as_ptr() as _,
                context().name_descriptor.short_name.as_ptr() as _,
                context().name_descriptor.filter_name.as_ptr() as _,
            );
            context_mut().privates.proto_handle = proto;

            context_mut().privates.hf = context_mut()
                .field_descriptors
                .iter_mut()
                .map(|x| match x {
                    &mut (
                        ref mut field,
                        EpanFieldDescriptor::String {
                            name: ref mut name,
                            abbrev: ref mut abbrev,
                        },
                    ) => sys::hf_register_info {
                        p_id: field,
                        hfinfo: sys::header_field_info {
                            name: name.as_ptr() as _,
                            abbrev: abbrev.as_ptr() as _,
                            type_: sys::ftenum_FT_STRING,
                            display: sys::field_display_e_BASE_NONE as _,
                            strings: ptr::null(),
                            bitmask: 0,
                            blurb: ptr::null(),
                            id: -1,
                            parent: 0,
                            ref_type: sys::hf_ref_type_HF_REF_TYPE_NONE,
                            same_name_prev_id: -1,
                            same_name_next: ptr::null_mut(),
                        },
                    },
                    &mut (
                        ref mut field,
                        EpanFieldDescriptor::Int64Dec {
                            name: ref mut name,
                            abbrev: ref mut abbrev,
                        },
                    ) => sys::hf_register_info {
                        p_id: field,
                        hfinfo: sys::header_field_info {
                            name: name.as_ptr() as _,
                            abbrev: abbrev.as_ptr() as _,
                            type_: sys::ftenum_FT_INT64,
                            display: sys::field_display_e_BASE_DEC as _,
                            strings: ptr::null(),
                            bitmask: 0,
                            blurb: ptr::null(),
                            id: -1,
                            parent: 0,
                            ref_type: sys::hf_ref_type_HF_REF_TYPE_NONE,
                            same_name_prev_id: -1,
                            same_name_next: ptr::null_mut(),
                        },
                    },
                })
                .collect();
            sys::proto_register_field_array(
                proto,
                context_mut().privates.hf.as_mut_ptr() as _,
                context().privates.hf.len() as _,
            );

            context_mut().privates.ett = context_mut().ett.iter_mut().collect();
            sys::proto_register_subtree_array(
                context_mut().privates.ett.as_mut_ptr() as _,
                context().privates.ett.len() as _,
            );

            unsafe extern "C" fn preferences_update_cb() {
                use std::ffi::CStr;

                if let Some(ref mut pref) = context_mut().pref_descriptor {
                    (pref.callback)(
                        context()
                            .privates
                            .pref_filenames
                            .iter()
                            .map(|&p| CStr::from_ptr(p).to_str().unwrap())
                            .collect(),
                    )
                }
            }

            if let Some(ref pref) = context().pref_descriptor {
                let prefs = sys::prefs_register_protocol(proto, Some(preferences_update_cb));
                context_mut()
                    .privates
                    .pref_filenames
                    .resize(pref.filename_fields.len(), ptr::null());
                for (i, d) in pref.filename_fields.iter().enumerate() {
                    sys::prefs_register_filename_preference(
                        prefs,
                        d.name.as_ptr() as _,
                        d.title.as_ptr() as _,
                        d.description.as_ptr() as _,
                        context_mut().privates.pref_filenames.get_mut(i).unwrap(),
                        0,
                    );
                }
            }
        }

        unsafe extern "C" fn register_handoff() {
            unsafe extern "C" fn heur_dissector(
                tvb: *mut sys::tvbuff_t,
                pinfo: *mut sys::packet_info,
                tree: *mut sys::proto_tree,
                data: *mut c_void,
            ) -> sys::gboolean {
                let d = &mut context_mut()
                    .dissector_descriptor
                    .as_mut()
                    .unwrap()
                    .dissector;
                let fields = context().fields();
                let info = DissectorInfo {
                    tvb: &mut *tvb,
                    pinfo: &mut *pinfo,
                    tree: &mut *tree,
                    mark: data as _,
                    fields: fields.clone(),
                    ett: context().ett.clone(),
                };
                if d.recognize(info) {
                    d.consume(DissectorInfo {
                        tvb: &mut *tvb,
                        pinfo: &mut *pinfo,
                        tree: &mut *tree,
                        mark: data as _,
                        fields: fields,
                        ett: context().ett.clone(),
                    });
                    1
                } else {
                    0
                }
            }

            unsafe extern "C" fn dissector(
                tvb: *mut sys::tvbuff_t,
                pinfo: *mut sys::packet_info,
                tree: *mut sys::proto_tree,
                data: *mut c_void,
            ) -> c_int {
                let d = &mut context_mut()
                    .dissector_descriptor
                    .as_mut()
                    .unwrap()
                    .dissector;
                let fields = context().fields();
                let info = DissectorInfo {
                    tvb: &mut *tvb,
                    pinfo: &mut *pinfo,
                    tree: &mut *tree,
                    mark: data as _,
                    fields: fields,
                    ett: context().ett.clone(),
                };
                d.consume(info) as _
            }

            if let Some(ref d) = context().dissector_descriptor {
                let proto_handle = context().privates.proto_handle;
                let handle = sys::create_dissector_handle(Some(dissector), proto_handle);
                sys::heur_dissector_add(
                    d.name.as_ptr() as _,
                    Some(heur_dissector),
                    d.display_name.as_ptr() as _,
                    d.short_name.as_ptr() as _,
                    proto_handle,
                    sys::heuristic_enable_e_HEURISTIC_ENABLE,
                );
                context_mut().privates.dissector_handle = handle;
            }
        }

        unsafe {
            CONTEXT = Some(self);
            context_mut().privates.plugin = sys::proto_plugin {
                register_protoinfo: Some(register_protoinfo),
                register_handoff: Some(register_handoff),
            };
            sys::proto_register_plugin(&context().privates.plugin);
        }
    }
}
