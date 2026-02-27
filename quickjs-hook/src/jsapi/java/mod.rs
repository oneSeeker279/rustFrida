//! Java.use() API — Frida-style Java method hooking
//!
//! Hooks ART methods by inline-patching the compiled code at the entry point.
//! On ARM64 Android, jmethodID == ArtMethod*. We resolve the method via JNI,
//! read the entry_point_from_quick_compiled_code_ field, then use the hook engine
//! to patch the actual compiled code (intercepting both direct BL and indirect calls).
//!
//! ## JS API
//!
//! ```javascript
//! var Activity = Java.use("android.app.Activity");
//! Activity.onResume.impl = function(ctx) { console.log("hit"); };
//! Activity.onResume.impl = null; // unhook
//! // For overloaded methods:
//! Activity.foo.overload("(II)V").impl = function(ctx) { ... };
//! ```

/// Transmute a JNI function pointer from the function table by index.
macro_rules! jni_fn {
    ($env:expr, $ty:ty, $idx:expr) => {
        std::mem::transmute::<*const std::ffi::c_void, $ty>(
            $crate::jsapi::java::jni_core::jni_fn_ptr($env, $idx)
        )
    };
}

mod jni_core;
mod reflect;
mod art_method;
mod callback;
mod js_api;

use crate::context::JSContext;
use crate::ffi;
use crate::ffi::hook as hook_ffi;
use crate::jsapi::console::output_message;
use crate::value::JSValue;
use std::ffi::CString;

use jni_core::*;
use reflect::*;
use callback::*;
use js_api::*;

/// Add a CFunction method to a JS object.
macro_rules! add_method {
    ($ctx:expr, $obj:expr, $name:expr, $func:expr, $argc:expr) => {{
        let cname = CString::new($name).unwrap();
        let func_val = ffi::qjs_new_cfunction($ctx, Some($func), cname.as_ptr(), $argc);
        let atom = ffi::JS_NewAtom($ctx, cname.as_ptr());
        ffi::qjs_set_property($ctx, $obj, atom, func_val);
        ffi::JS_FreeAtom($ctx, atom);
    }};
}

/// Register Java API: hook/unhook (C-level) + _methods, then eval boot script
/// to set up the Proxy-based Java.use() API.
pub fn register_java_api(ctx: &JSContext) {
    // Pre-cache reflection method IDs from the safe init thread.
    // This must happen here (not from hook callbacks) because FindClass
    // triggers ART stack walking, which crashes inside hook trampolines.
    if let Ok(env) = ensure_jni_initialized() {
        unsafe {
            cache_reflect_ids(env);
        }
    }

    let global = ctx.global_object();

    unsafe {
        // Create the "Java" namespace object
        let java_obj = ffi::JS_NewObject(ctx.as_ptr());

        add_method!(ctx.as_ptr(), java_obj, "hook", js_java_hook, 4);
        add_method!(ctx.as_ptr(), java_obj, "unhook", js_java_unhook, 3);
        add_method!(ctx.as_ptr(), java_obj, "_methods", js_java_methods, 1);
        add_method!(ctx.as_ptr(), java_obj, "_getFieldAuto", js_java_get_field_auto, 3);
        add_method!(ctx.as_ptr(), java_obj, "getField", js_java_get_field, 4);

        // Set Java object on global
        global.set_property(ctx.as_ptr(), "Java", JSValue(java_obj));
    }

    global.free(ctx.as_ptr());

    // Load boot script: sets up Java.use() Proxy API, captures hook/unhook/
    // _methods in closures, then removes them from the Java object.
    let boot = include_str!("java_boot.js");
    match ctx.eval(boot, "<java_boot>") {
        Ok(val) => val.free(ctx.as_ptr()),
        Err(e) => output_message(&format!("[java_api] boot script error: {}", e)),
    }
}

/// Cleanup all Java hooks (call before dropping context)
pub fn cleanup_java_hooks() {
    // Get JNIEnv for global ref cleanup (best effort)
    let env_opt = unsafe { get_thread_env().ok() };

    let mut guard = JAVA_HOOK_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(registry) = guard.take() {
        for (_art_method, data) in registry {
            unsafe {
                // Remove native trampoline from hook engine
                hook_ffi::hook_remove_redirect(data.art_method);

                // Restore original ArtMethod state
                if let Some(&ep_offset) = ENTRY_POINT_OFFSET.get() {
                    let flags_ptr = (data.art_method as usize + ART_METHOD_ACCESS_FLAGS_OFFSET)
                        as *mut u32;
                    std::ptr::write_volatile(flags_ptr, data.original_access_flags);

                    let data_ptr = (data.art_method as usize + ART_METHOD_DATA_OFFSET) as *mut u64;
                    std::ptr::write_volatile(data_ptr, data.original_data);

                    let ep_ptr = (data.art_method as usize + ep_offset) as *mut u64;
                    std::ptr::write_volatile(ep_ptr, data.original_entry_point);
                }

                // Free ArtMethod clone
                if data.clone_addr != 0 {
                    libc::free(data.clone_addr as *mut std::ffi::c_void);
                }

                // Delete JNI global ref
                if data.class_global_ref != 0 {
                    if let Some(env) = env_opt {
                        let delete_global_ref: DeleteGlobalRefFn =
                            jni_fn!(env, DeleteGlobalRefFn, JNI_DELETE_GLOBAL_REF);
                        delete_global_ref(env, data.class_global_ref as *mut std::ffi::c_void);
                    }
                }

                // Free JS callback
                let ctx = data.ctx as *mut ffi::JSContext;
                let callback: ffi::JSValue =
                    std::ptr::read(data.callback_bytes.as_ptr() as *const ffi::JSValue);
                ffi::qjs_free_value(ctx, callback);
            }
        }
    }
}
