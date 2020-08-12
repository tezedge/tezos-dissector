use std::os::raw::{c_int, c_char};
use super::sys;

struct EpanPluginPrivates<'a> {
    plugin: sys::proto_plugin,
    hf: Vec<sys::hf_register_info>,
    ett: Vec<&'a mut c_int>,
    pref_filenames: Vec<*const c_char>,
}

impl<'a> EpanPluginPrivates<'a> {
    pub fn empty() -> Self {
        EpanPluginPrivates {
            plugin: sys::proto_plugin {
                register_protoinfo: None,
                register_handoff: None,
            },
            hf: Vec::new(),
            ett: Vec::new(),
            pref_filenames: Vec::new(),
        }
    }
}

pub struct EpanPlugin<'a> {
    privates: EpanPluginPrivates<'a>,
    proto: Option<i32>,
    name_descriptor: EpanNameDescriptor<'a>,
    field_descriptors: Vec<(i32, EpanFieldDescriptor<'a>)>,
    ett: Vec<i32>,
    pref_descriptor: Option<EpanPrefDescriptor<'a>>,
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

impl<'a> EpanPlugin<'a> {
    pub fn new(name_descriptor: EpanNameDescriptor<'a>) -> Self {
        EpanPlugin {
            privates: EpanPluginPrivates::empty(),
            name_descriptor: name_descriptor,
            proto: None,
            field_descriptors: Vec::new(),
            ett: Vec::new(),
            pref_descriptor: None,
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
}

impl EpanPlugin<'static> {
    pub fn register(self) {
        use std::ptr;

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
            context_mut().proto = Some(proto);

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

        unsafe extern "C" fn register_handoff() {}

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
