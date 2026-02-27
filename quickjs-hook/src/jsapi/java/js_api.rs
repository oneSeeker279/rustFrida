//! JavaScript API functions for Java hooking
//!
//! Contains: js_java_hook, js_java_unhook, js_java_methods,
//! ObjectFieldMode, read_field_value, js_java_get_field, js_java_get_field_auto.

use crate::ffi;
use crate::ffi::hook as hook_ffi;
use crate::jsapi::console::output_message;
use crate::value::JSValue;
use std::ffi::CString;

use super::jni_core::*;
use super::reflect::*;
use super::art_method::*;
use super::callback::*;

// ============================================================================
// JS API: Java.hook(class, method, sig, callback)
// ============================================================================

pub(super) unsafe extern "C" fn js_java_hook(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 4 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"Java.hook() requires 4 arguments: class, method, signature, callback\0".as_ptr()
                as *const _,
        );
    }

    let class_arg = JSValue(*argv);
    let method_arg = JSValue(*argv.add(1));
    let sig_arg = JSValue(*argv.add(2));
    let callback_arg = JSValue(*argv.add(3));

    // Extract string arguments
    let class_name = match class_arg.to_string(ctx) {
        Some(s) => s,
        None => {
            return ffi::JS_ThrowTypeError(
                ctx,
                b"Java.hook() first argument must be a class name string\0".as_ptr() as *const _,
            )
        }
    };

    let method_name = match method_arg.to_string(ctx) {
        Some(s) => s,
        None => {
            return ffi::JS_ThrowTypeError(
                ctx,
                b"Java.hook() second argument must be a method name string\0".as_ptr() as *const _,
            )
        }
    };

    let sig_str = match sig_arg.to_string(ctx) {
        Some(s) => s,
        None => {
            return ffi::JS_ThrowTypeError(
                ctx,
                b"Java.hook() third argument must be a signature string\0".as_ptr() as *const _,
            )
        }
    };

    if !callback_arg.is_function(ctx) {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"Java.hook() fourth argument must be a function\0".as_ptr() as *const _,
        );
    }

    // Parse "static:" prefix
    let (actual_sig, force_static) = if let Some(stripped) = sig_str.strip_prefix("static:") {
        (stripped.to_string(), true)
    } else {
        (sig_str.clone(), false)
    };

    // Initialize JNI
    let env = match ensure_jni_initialized() {
        Ok(e) => e,
        Err(msg) => {
            let err = CString::new(msg).unwrap();
            return ffi::JS_ThrowInternalError(ctx, err.as_ptr());
        }
    };

    // Resolve ArtMethod
    let (art_method, is_static) = match resolve_art_method(env, &class_name, &method_name, &actual_sig, force_static) {
        Ok(r) => r,
        Err(msg) => {
            let err = CString::new(msg).unwrap();
            return ffi::JS_ThrowInternalError(ctx, err.as_ptr());
        }
    };

    // Check if already hooked
    init_java_registry();
    {
        let guard = JAVA_HOOK_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(ref registry) = *guard {
            if registry.contains_key(&art_method) {
                return ffi::JS_ThrowInternalError(
                    ctx,
                    b"method already hooked (unhook first)\0".as_ptr() as *const _,
                );
            }
        }
    }

    // Probe entry_point offset (lazy, one-time)
    let ep_offset = get_entry_point_offset(env, art_method);

    // ================================================================
    // "Replace with native" approach (Frida-style)
    //
    // Convert the method to native by modifying its ArtMethod:
    //   1. Set kAccNative in access_flags_ → ART treats it as a native method
    //   2. Write our thunk address to data_ → ART calls our thunk via JNI trampoline
    //   3. Write generic JNI trampoline to entry_point_ → ART dispatches here
    //
    // This works for ALL methods (interpreted, OAT, JIT) because:
    //   - Native methods always go through the JNI trampoline
    //   - Virtual dispatch always reads entry_point from the ArtMethod
    //   - No inline patching of shared code
    // ================================================================

    // Save original method state for unhook
    let original_access_flags = {
        std::ptr::read_volatile(
            (art_method as usize + ART_METHOD_ACCESS_FLAGS_OFFSET) as *const u32,
        )
    };
    let original_data = {
        std::ptr::read_volatile(
            (art_method as usize + ART_METHOD_DATA_OFFSET) as *const u64,
        )
    };
    let original_entry_point = read_entry_point(art_method, ep_offset);

    output_message(&format!(
        "[java hook] art_method={:#x}, orig_flags={:#x}, orig_data={:#x}, orig_entry={:#x}",
        art_method, original_access_flags, original_data, original_entry_point
    ));

    // Clone ArtMethod for callOriginal (Frida pattern)
    // The clone preserves the original method state. callOriginal() invokes the clone
    // via JNI CallNonvirtual*MethodA which reads the clone's original quickCode.
    let clone_size = ep_offset + 8; // includes entry_point field
    let clone_addr = {
        let ptr = libc::malloc(clone_size);
        if ptr.is_null() {
            let err = CString::new("malloc failed for ArtMethod clone").unwrap();
            return ffi::JS_ThrowInternalError(ctx, err.as_ptr());
        }
        std::ptr::copy_nonoverlapping(
            art_method as *const u8,
            ptr as *mut u8,
            clone_size,
        );
        ptr as u64
    };
    output_message(&format!(
        "[java hook] ArtMethod clone at {:#x} (size={})", clone_addr, clone_size
    ));

    // Create JNI global ref to the class for callOriginal JNI calls
    let class_global_ref = {
        let cls = find_class_safe(env, &class_name);
        if cls.is_null() {
            libc::free(clone_addr as *mut std::ffi::c_void);
            let err = CString::new(format!("FindClass('{}') failed for global ref", class_name)).unwrap();
            return ffi::JS_ThrowInternalError(ctx, err.as_ptr());
        }
        let new_global_ref: NewGlobalRefFn = jni_fn!(env, NewGlobalRefFn, JNI_NEW_GLOBAL_REF);
        let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
        let gref = new_global_ref(env, cls);
        delete_local_ref(env, cls);
        gref as usize
    };

    // Extract return type from signature
    let return_type = get_return_type_from_sig(&actual_sig);

    // Find the generic JNI trampoline address (optional — we may keep original entry_point)
    let jni_trampoline = find_jni_trampoline(env, ep_offset);

    // Create native hook trampoline (per-method thunk called by ART's JNI machinery)
    let thunk = hook_ffi::hook_create_native_trampoline(
        art_method,                          // key = ArtMethod*
        Some(java_hook_callback),            // on_enter callback
        art_method as *mut std::ffi::c_void, // user_data = ArtMethod* for registry lookup
    );

    if thunk.is_null() {
        libc::free(clone_addr as *mut std::ffi::c_void);
        let err = CString::new("hook_create_native_trampoline failed").unwrap();
        return ffi::JS_ThrowInternalError(ctx, err.as_ptr());
    }

    // Duplicate callback and store in registry BEFORE modifying ArtMethod
    let callback_dup = ffi::qjs_dup_value(ctx, callback_arg.raw());
    let mut callback_bytes = [0u8; 16];
    std::ptr::copy_nonoverlapping(
        &callback_dup as *const ffi::JSValue as *const u8,
        callback_bytes.as_mut_ptr(),
        16,
    );

    {
        let mut guard = JAVA_HOOK_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
        let registry = guard.as_mut().unwrap();
        registry.insert(
            art_method,
            JavaHookData {
                art_method,
                original_access_flags,
                original_data,
                original_entry_point,
                clone_addr,
                class_global_ref,
                return_type,
                method_id_raw: art_method, // decoded art_method is the raw pointer
                ctx: ctx as usize,
                callback_bytes,
                method_key: method_key(&class_name, &method_name, &actual_sig),
                is_static,
                param_count: count_jni_params(&actual_sig),
            },
        );
    }

    // === Modify ArtMethod to become a "native" method ===

    // 1. Set access flags for native hook
    set_native_hook_flags(art_method);

    // 2. Write our native thunk address to data_ (the JNI native function pointer)
    {
        let data_ptr = (art_method as usize + ART_METHOD_DATA_OFFSET) as *mut u64;
        std::ptr::write_volatile(data_ptr, thunk as u64);
    }

    // 3. Set entry_point to the generic JNI trampoline.
    //    This is REQUIRED: the interpreter bridge crashes if kAccNative is set
    //    because it tries to read data_ as DEX bytecode.
    {
        if jni_trampoline != 0 {
            let ep_ptr = (art_method as usize + ep_offset) as *mut u64;
            std::ptr::write_volatile(ep_ptr, jni_trampoline);
        } else {
            output_message("[java hook] WARNING: JNI trampoline not found, hook will likely crash!");
        }
        hook_ffi::hook_flush_cache(
            (art_method as usize) as *mut std::ffi::c_void,
            ep_offset + 8,
        );
    }

    // Verify writes
    let verify_flags = {
        std::ptr::read_volatile(
            (art_method as usize + ART_METHOD_ACCESS_FLAGS_OFFSET) as *const u32,
        )
    };
    let verify_data = {
        std::ptr::read_volatile(
            (art_method as usize + ART_METHOD_DATA_OFFSET) as *const u64,
        )
    };
    let verify_ep = read_entry_point(art_method, ep_offset);

    output_message(&format!(
        "[java hook] native hook installed: flags={:#x}, data(thunk)={:#x}, entry={:#x} (jni_tramp={:#x})",
        verify_flags, verify_data, verify_ep, jni_trampoline
    ));

    // Pre-cache field info for this class (safe from init thread)
    cache_fields_for_class(env, &class_name);

    output_message(&format!(
        "[java hook] hooked {}.{}{} (ArtMethod={:#x}, strategy=replace-with-native)",
        class_name, method_name, actual_sig, art_method
    ));

    JSValue::bool(true).raw()
}

// ============================================================================
// JS API: Java.unhook(class, method, sig)
// ============================================================================

pub(super) unsafe extern "C" fn js_java_unhook(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 3 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"Java.unhook() requires 3 arguments: class, method, signature\0".as_ptr()
                as *const _,
        );
    }

    let class_arg = JSValue(*argv);
    let method_arg = JSValue(*argv.add(1));
    let sig_arg = JSValue(*argv.add(2));

    let class_name = match class_arg.to_string(ctx) {
        Some(s) => s,
        None => {
            return ffi::JS_ThrowTypeError(
                ctx,
                b"Java.unhook() first argument must be a string\0".as_ptr() as *const _,
            )
        }
    };

    let method_name = match method_arg.to_string(ctx) {
        Some(s) => s,
        None => {
            return ffi::JS_ThrowTypeError(
                ctx,
                b"Java.unhook() second argument must be a string\0".as_ptr() as *const _,
            )
        }
    };

    let sig_str = match sig_arg.to_string(ctx) {
        Some(s) => s,
        None => {
            return ffi::JS_ThrowTypeError(
                ctx,
                b"Java.unhook() third argument must be a string\0".as_ptr() as *const _,
            )
        }
    };

    // Handle "static:" prefix
    let actual_sig = if let Some(stripped) = sig_str.strip_prefix("static:") {
        stripped.to_string()
    } else {
        sig_str
    };

    let key = method_key(&class_name, &method_name, &actual_sig);

    // Find and remove from registry
    let hook_data = {
        let mut guard = JAVA_HOOK_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(registry) = guard.as_mut() {
            // Find by method_key
            let art_method = registry
                .iter()
                .find(|(_, v)| v.method_key == key)
                .map(|(k, _)| *k);

            if let Some(am) = art_method {
                registry.remove(&am)
            } else {
                None
            }
        } else {
            None
        }
    };

    let hook_data = match hook_data {
        Some(d) => d,
        None => {
            return ffi::JS_ThrowInternalError(
                ctx,
                b"method not hooked\0".as_ptr() as *const _,
            );
        }
    };

    // Remove the native trampoline from the hook engine
    hook_ffi::hook_remove_redirect(hook_data.art_method);

    // Restore original ArtMethod state
    if let Some(&ep_offset) = ENTRY_POINT_OFFSET.get() {
        // Restore access_flags_
        let flags_ptr = (hook_data.art_method as usize + ART_METHOD_ACCESS_FLAGS_OFFSET)
            as *mut u32;
        std::ptr::write_volatile(flags_ptr, hook_data.original_access_flags);

        // Restore data_
        let data_ptr = (hook_data.art_method as usize + ART_METHOD_DATA_OFFSET) as *mut u64;
        std::ptr::write_volatile(data_ptr, hook_data.original_data);

        // Restore entry_point
        let ep_ptr = (hook_data.art_method as usize + ep_offset) as *mut u64;
        std::ptr::write_volatile(ep_ptr, hook_data.original_entry_point);

        hook_ffi::hook_flush_cache(
            (hook_data.art_method as usize) as *mut std::ffi::c_void,
            ep_offset + 8,
        );
    }

    // Free the ArtMethod clone
    if hook_data.clone_addr != 0 {
        libc::free(hook_data.clone_addr as *mut std::ffi::c_void);
    }

    // Delete the JNI global ref to the class
    if hook_data.class_global_ref != 0 {
        if let Ok(env) = get_thread_env() {
            let delete_global_ref: DeleteGlobalRefFn =
                jni_fn!(env, DeleteGlobalRefFn, JNI_DELETE_GLOBAL_REF);
            delete_global_ref(env, hook_data.class_global_ref as *mut std::ffi::c_void);
        }
    }

    // Free the JS callback
    let js_ctx = hook_data.ctx as *mut ffi::JSContext;
    let callback: ffi::JSValue =
        std::ptr::read(hook_data.callback_bytes.as_ptr() as *const ffi::JSValue);
    ffi::qjs_free_value(js_ctx, callback);

    output_message(&format!(
        "[java hook] unhooked {}.{}{}",
        class_name, method_name, actual_sig
    ));

    JSValue::bool(true).raw()
}

// ============================================================================
// JS API: Java._methods(class) — enumerate methods via JNI reflection
// ============================================================================

pub(super) unsafe extern "C" fn js_java_methods(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"_methods() requires 1 argument: className\0".as_ptr() as *const _,
        );
    }

    let class_arg = JSValue(*argv);
    let class_name = match class_arg.to_string(ctx) {
        Some(s) => s,
        None => {
            return ffi::JS_ThrowTypeError(
                ctx,
                b"argument must be a class name string\0".as_ptr() as *const _,
            )
        }
    };

    let env = match ensure_jni_initialized() {
        Ok(e) => e,
        Err(msg) => {
            let err = CString::new(msg).unwrap();
            return ffi::JS_ThrowInternalError(ctx, err.as_ptr());
        }
    };

    let methods = match enumerate_methods(env, &class_name) {
        Ok(m) => m,
        Err(msg) => {
            let err = CString::new(msg).unwrap();
            return ffi::JS_ThrowInternalError(ctx, err.as_ptr());
        }
    };

    // Build JS array: [{name: "...", sig: "...", static: bool}, ...]
    let arr = ffi::JS_NewArray(ctx);
    for (i, m) in methods.iter().enumerate() {
        let obj = ffi::JS_NewObject(ctx);
        let obj_val = JSValue(obj);

        let name_val = JSValue::string(ctx, &m.name);
        let sig_val = JSValue::string(ctx, &m.sig);
        let static_val = JSValue::bool(m.is_static);

        obj_val.set_property(ctx, "name", name_val);
        obj_val.set_property(ctx, "sig", sig_val);
        obj_val.set_property(ctx, "static", static_val);

        ffi::JS_SetPropertyUint32(ctx, arr, i as u32, obj);
    }

    arr
}

// ============================================================================
// Shared field-value reader (used by getField and _getFieldAuto)
// ============================================================================

pub(super) enum ObjectFieldMode {
    RawPointer,
    WrappedProxy { type_name: String },
}

/// Read a single field value from a JNI object, dispatching on the JNI type signature.
/// For 'L'/'[' fields: String fields become JS strings; other objects are handled
/// according to `mode` (RawPointer returns BigUint64, WrappedProxy returns {__jptr, __jclass}).
unsafe fn read_field_value(
    ctx: *mut ffi::JSContext,
    env: JniEnv,
    obj: *mut std::ffi::c_void,
    field_id: *mut std::ffi::c_void,
    jni_sig: &str,
    mode: ObjectFieldMode,
) -> ffi::JSValue {
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);

    let sig_bytes = jni_sig.as_bytes();
    match sig_bytes.first() {
        Some(b'Z') => {
            let f: GetBooleanFieldFn = jni_fn!(env, GetBooleanFieldFn, JNI_GET_BOOLEAN_FIELD);
            JSValue::bool(f(env, obj, field_id) != 0).raw()
        }
        Some(b'B') => {
            let f: GetByteFieldFn = jni_fn!(env, GetByteFieldFn, JNI_GET_BYTE_FIELD);
            JSValue::int(f(env, obj, field_id) as i32).raw()
        }
        Some(b'C') => {
            let f: GetCharFieldFn = jni_fn!(env, GetCharFieldFn, JNI_GET_CHAR_FIELD);
            JSValue::int(f(env, obj, field_id) as i32).raw()
        }
        Some(b'S') => {
            let f: GetShortFieldFn = jni_fn!(env, GetShortFieldFn, JNI_GET_SHORT_FIELD);
            JSValue::int(f(env, obj, field_id) as i32).raw()
        }
        Some(b'I') => {
            let f: GetIntFieldFn = jni_fn!(env, GetIntFieldFn, JNI_GET_INT_FIELD);
            JSValue::int(f(env, obj, field_id)).raw()
        }
        Some(b'J') => {
            let f: GetLongFieldFn = jni_fn!(env, GetLongFieldFn, JNI_GET_LONG_FIELD);
            ffi::JS_NewBigUint64(ctx, f(env, obj, field_id) as u64)
        }
        Some(b'F') => {
            let f: GetFloatFieldFn = jni_fn!(env, GetFloatFieldFn, JNI_GET_FLOAT_FIELD);
            JSValue::float(f(env, obj, field_id) as f64).raw()
        }
        Some(b'D') => {
            let f: GetDoubleFieldFn = jni_fn!(env, GetDoubleFieldFn, JNI_GET_DOUBLE_FIELD);
            JSValue::float(f(env, obj, field_id)).raw()
        }
        Some(b'L') | Some(b'[') => {
            let f: GetObjectFieldFn = jni_fn!(env, GetObjectFieldFn, JNI_GET_OBJECT_FIELD);
            let obj_val = f(env, obj, field_id);

            if obj_val.is_null() {
                return ffi::qjs_null();
            }

            // Check if String type
            if jni_sig == "Ljava/lang/String;" {
                let get_str: GetStringUtfCharsFn = jni_fn!(env, GetStringUtfCharsFn, JNI_GET_STRING_UTF_CHARS);
                let rel_str: ReleaseStringUtfCharsFn = jni_fn!(env, ReleaseStringUtfCharsFn, JNI_RELEASE_STRING_UTF_CHARS);

                let chars = get_str(env, obj_val, std::ptr::null_mut());
                let js_result = if !chars.is_null() {
                    let s = std::ffi::CStr::from_ptr(chars)
                        .to_string_lossy()
                        .to_string();
                    rel_str(env, obj_val, chars);
                    JSValue::string(ctx, &s).raw()
                } else {
                    ffi::qjs_null()
                };
                delete_local_ref(env, obj_val);
                return js_result;
            }

            match mode {
                ObjectFieldMode::RawPointer => {
                    let ptr_val = obj_val as u64;
                    delete_local_ref(env, obj_val);
                    ffi::JS_NewBigUint64(ctx, ptr_val)
                }
                ObjectFieldMode::WrappedProxy { ref type_name } => {
                    let wrapper = ffi::JS_NewObject(ctx);
                    let wrapper_val = JSValue(wrapper);

                    let ptr_val = ffi::JS_NewBigUint64(ctx, obj_val as u64);
                    wrapper_val.set_property(ctx, "__jptr", JSValue(ptr_val));

                    let cls_val = JSValue::string(ctx, type_name);
                    wrapper_val.set_property(ctx, "__jclass", cls_val);

                    // Don't delete obj_val — keep local ref alive for chained access
                    wrapper
                }
            }
        }
        _ => ffi::qjs_undefined(),
    }
}

// ============================================================================
// JS API: Java.getField(objPtr, className, fieldName, fieldSig)
// ============================================================================

pub(super) unsafe extern "C" fn js_java_get_field(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    use crate::jsapi::ptr::get_native_pointer_addr;

    if argc < 4 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"Java.getField() requires 4 arguments: objPtr, className, fieldName, fieldSig\0"
                .as_ptr() as *const _,
        );
    }

    let obj_arg = JSValue(*argv);
    let class_arg = JSValue(*argv.add(1));
    let method_arg = JSValue(*argv.add(2));
    let sig_arg = JSValue(*argv.add(3));

    // Extract objPtr — try NativePointer first, then BigUint64/Number
    let obj_ptr = if let Some(addr) = get_native_pointer_addr(ctx, obj_arg) {
        addr
    } else if let Some(addr) = obj_arg.to_u64(ctx) {
        addr
    } else {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"Java.getField() first argument must be a pointer (BigUint64/Number/NativePointer)\0"
                .as_ptr() as *const _,
        );
    };

    if obj_ptr == 0 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"Java.getField() objPtr is null\0".as_ptr() as *const _,
        );
    }

    let class_name = match class_arg.to_string(ctx) {
        Some(s) => s,
        None => {
            return ffi::JS_ThrowTypeError(
                ctx,
                b"Java.getField() className must be a string\0".as_ptr() as *const _,
            )
        }
    };

    let field_name = match method_arg.to_string(ctx) {
        Some(s) => s,
        None => {
            return ffi::JS_ThrowTypeError(
                ctx,
                b"Java.getField() fieldName must be a string\0".as_ptr() as *const _,
            )
        }
    };

    let field_sig = match sig_arg.to_string(ctx) {
        Some(s) => s,
        None => {
            return ffi::JS_ThrowTypeError(
                ctx,
                b"Java.getField() fieldSig must be a string\0".as_ptr() as *const _,
            )
        }
    };

    // Get thread-safe JNIEnv*
    let env = match get_thread_env() {
        Ok(e) => e,
        Err(msg) => {
            let err = CString::new(msg).unwrap();
            return ffi::JS_ThrowInternalError(ctx, err.as_ptr());
        }
    };

    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
    let new_local_ref: NewLocalRefFn = jni_fn!(env, NewLocalRefFn, JNI_NEW_LOCAL_REF);
    let get_field_id: GetFieldIdFn = jni_fn!(env, GetFieldIdFn, JNI_GET_FIELD_ID);

    // FindClass — use find_class_safe to support app classes
    let cls = find_class_safe(env, &class_name);
    if cls.is_null() {
        let err = CString::new(format!("FindClass('{}') failed", class_name)).unwrap();
        return ffi::JS_ThrowInternalError(ctx, err.as_ptr());
    }

    // NewLocalRef — wrap raw mirror pointer as a proper JNI local ref
    let local_obj = new_local_ref(env, obj_ptr as *mut std::ffi::c_void);
    if local_obj.is_null() {
        delete_local_ref(env, cls);
        return ffi::JS_ThrowInternalError(
            ctx,
            b"NewLocalRef failed for objPtr\0".as_ptr() as *const _,
        );
    }

    // GetFieldID
    let c_field = match CString::new(field_name.as_str()) {
        Ok(c) => c,
        Err(_) => {
            delete_local_ref(env, local_obj);
            delete_local_ref(env, cls);
            return ffi::JS_ThrowTypeError(
                ctx,
                b"invalid field name\0".as_ptr() as *const _,
            );
        }
    };
    let c_sig = match CString::new(field_sig.as_str()) {
        Ok(c) => c,
        Err(_) => {
            delete_local_ref(env, local_obj);
            delete_local_ref(env, cls);
            return ffi::JS_ThrowTypeError(
                ctx,
                b"invalid field signature\0".as_ptr() as *const _,
            );
        }
    };

    let field_id = get_field_id(env, cls, c_field.as_ptr(), c_sig.as_ptr());
    if field_id.is_null() || jni_check_exc(env) {
        delete_local_ref(env, local_obj);
        delete_local_ref(env, cls);
        let err = CString::new(format!(
            "GetFieldID failed: {}.{} (sig={})",
            class_name, field_name, field_sig
        ))
        .unwrap();
        return ffi::JS_ThrowInternalError(ctx, err.as_ptr());
    }

    // Check for unsupported signature before calling read_field_value
    let sig_first = field_sig.as_bytes().first().copied();
    if !matches!(sig_first, Some(b'Z' | b'B' | b'C' | b'S' | b'I' | b'J' | b'F' | b'D' | b'L' | b'[')) {
        delete_local_ref(env, local_obj);
        delete_local_ref(env, cls);
        let err = CString::new(format!("unsupported field signature: {}", field_sig)).unwrap();
        return ffi::JS_ThrowTypeError(ctx, err.as_ptr());
    }

    // Dispatch via shared helper (RawPointer mode — returns BigUint64 for objects)
    let result = read_field_value(ctx, env, local_obj, field_id, &field_sig, ObjectFieldMode::RawPointer);

    // Check for JNI exception after field access
    if jni_check_exc(env) {
        delete_local_ref(env, local_obj);
        delete_local_ref(env, cls);
        let err = CString::new(format!(
            "JNI exception reading field {}.{}",
            class_name, field_name
        ))
        .unwrap();
        return ffi::JS_ThrowInternalError(ctx, err.as_ptr());
    }

    delete_local_ref(env, local_obj);
    delete_local_ref(env, cls);
    result
}

// ============================================================================
// JS API: Java._getFieldAuto(objPtr, className, fieldName)
//   Auto-detects field type via JNI reflection, returns value directly.
//   Returns undefined for missing fields (Proxy-friendly).
// ============================================================================

pub(super) unsafe extern "C" fn js_java_get_field_auto(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    use crate::jsapi::ptr::get_native_pointer_addr;

    if argc < 3 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"_getFieldAuto() requires 3 arguments: objPtr, className, fieldName\0".as_ptr()
                as *const _,
        );
    }

    let obj_arg = JSValue(*argv);
    let _class_arg = JSValue(*argv.add(1));
    let field_arg = JSValue(*argv.add(2));

    // Extract objPtr
    let obj_ptr = if let Some(addr) = get_native_pointer_addr(ctx, obj_arg) {
        addr
    } else if let Some(addr) = obj_arg.to_u64(ctx) {
        addr
    } else {
        return ffi::qjs_undefined();
    };

    if obj_ptr == 0 {
        return ffi::qjs_null();
    }

    let field_name = match field_arg.to_string(ctx) {
        Some(s) => s,
        None => return ffi::qjs_undefined(),
    };

    // Look up field in pre-computed cache (safe — no JNI reflection calls)
    let (jni_sig, field_id, type_name) = {
        let guard = FIELD_CACHE.lock().unwrap_or_else(|e| e.into_inner());
        let cache = match guard.as_ref() {
            Some(c) => c,
            None => return ffi::qjs_undefined(),
        };
        // className is passed from the Proxy wrapper (e.g. "android.app.Activity")
        let class_name = match _class_arg.to_string(ctx) {
            Some(s) => s,
            None => return ffi::qjs_undefined(),
        };
        let class_fields = match cache.get(&class_name) {
            Some(f) => f,
            None => return ffi::qjs_undefined(),
        };
        let info = match class_fields.get(&field_name) {
            Some(i) => i,
            None => return ffi::qjs_undefined(), // field not found
        };
        // Extract the type name from jni_sig for object handling
        let tn = match info.jni_sig.as_bytes().first() {
            Some(b'L') => {
                // "Ljava/lang/String;" → "java.lang.String"
                let inner = &info.jni_sig[1..info.jni_sig.len() - 1];
                inner.replace('/', ".")
            }
            _ => String::new(),
        };
        (info.jni_sig.clone(), info.field_id, tn)
    };

    // Get thread-safe JNIEnv*
    let env = match get_thread_env() {
        Ok(e) => e,
        Err(_) => return ffi::qjs_undefined(),
    };

    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
    let new_local_ref: NewLocalRefFn = jni_fn!(env, NewLocalRefFn, JNI_NEW_LOCAL_REF);

    // NewLocalRef — wraps raw mirror pointer as JNI local ref
    let local_obj = new_local_ref(env, obj_ptr as *mut std::ffi::c_void);
    if local_obj.is_null() {
        return ffi::qjs_undefined();
    }

    // Dispatch via shared helper (WrappedProxy mode — returns {__jptr, __jclass} for objects)
    let mode = ObjectFieldMode::WrappedProxy { type_name: type_name.clone() };
    let result = read_field_value(ctx, env, local_obj, field_id, &jni_sig, mode);

    // Check for JNI exception
    jni_check_exc(env);

    delete_local_ref(env, local_obj);
    result
}
