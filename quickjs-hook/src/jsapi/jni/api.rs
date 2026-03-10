use crate::context::JSContext;
use crate::ffi;
use crate::jsapi::callback_util::extract_pointer_address;
use crate::jsapi::java::ensure_jni_initialized;
use crate::jsapi::ptr::create_native_pointer;
use crate::jsapi::util::add_cfunction_to_object;
use crate::value::JSValue;
use std::ffi::CString;

use super::load_jni_boot_script;

unsafe extern "C" fn js_jni_class_name(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 2 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"Jni._className() requires 2 arguments: envPtr, classPtr\0".as_ptr() as *const _,
        );
    }

    let env_ptr = match extract_pointer_address(ctx, JSValue(*argv), "Jni._className") {
        Ok(v) => v,
        Err(err) => return err,
    };
    let cls_ptr = match extract_pointer_address(ctx, JSValue(*argv.add(1)), "Jni._className") {
        Ok(v) => v,
        Err(err) => return err,
    };

    match crate::jsapi::java::get_class_name_unchecked(env_ptr, cls_ptr) {
        Some(name) => JSValue::string(ctx, &name).raw(),
        None => JSValue::null().raw(),
    }
}

unsafe extern "C" fn js_jni_thread_env(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    match ensure_jni_initialized() {
        Ok(env) => create_native_pointer(ctx, env as usize as u64).raw(),
        Err(err) => {
            let msg = CString::new(format!("Jni current thread env init failed: {}", err))
                .unwrap_or_default();
            ffi::JS_ThrowInternalError(ctx, msg.as_ptr())
        }
    }
}

pub fn register_jni_api(ctx: &JSContext) {
    let global = ctx.global_object();

    unsafe {
        let ctx_ptr = ctx.as_ptr();
        let jni_obj = ffi::JS_NewObject(ctx_ptr);
        add_cfunction_to_object(ctx_ptr, jni_obj, "_className", js_jni_class_name, 2);
        add_cfunction_to_object(ctx_ptr, jni_obj, "_threadEnv", js_jni_thread_env, 0);
        global.set_property(ctx_ptr, "Jni", JSValue(jni_obj));
    }

    global.free(ctx.as_ptr());
    load_jni_boot_script(ctx);
}
