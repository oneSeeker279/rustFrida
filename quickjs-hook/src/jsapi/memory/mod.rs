//! Memory API implementation

mod helpers;
mod read;
mod write;

use crate::context::JSContext;
use crate::ffi;
use std::ffi::CString;

use read::*;
use write::*;

/// Register Memory API
pub fn register_memory_api(ctx: &JSContext) {
    let global = ctx.global_object();
    let memory = ctx.new_object();

    macro_rules! add_method {
        ($name:expr, $func:expr) => {
            unsafe {
                let cname = CString::new($name).unwrap();
                let func_val = ffi::qjs_new_cfunction(ctx.as_ptr(), Some($func), cname.as_ptr(), 0);
                let prop_name = CString::new($name).unwrap();
                let atom = ffi::JS_NewAtom(ctx.as_ptr(), prop_name.as_ptr());
                ffi::qjs_set_property(ctx.as_ptr(), memory.raw(), atom, func_val);
                ffi::JS_FreeAtom(ctx.as_ptr(), atom);
            }
        };
    }

    add_method!("readU8", memory_read_u8);
    add_method!("readU16", memory_read_u16);
    add_method!("readU32", memory_read_u32);
    add_method!("readU64", memory_read_u64);
    add_method!("readPointer", memory_read_pointer);
    add_method!("readCString", memory_read_cstring);
    add_method!("readUtf8String", memory_read_utf8_string);
    add_method!("readByteArray", memory_read_byte_array);
    add_method!("writeU8", memory_write_u8);
    add_method!("writeU16", memory_write_u16);
    add_method!("writeU32", memory_write_u32);
    add_method!("writeU64", memory_write_u64);
    add_method!("writePointer", memory_write_pointer);

    // Set Memory on global object
    global.set_property(ctx.as_ptr(), "Memory", memory);
    global.free(ctx.as_ptr());
}
