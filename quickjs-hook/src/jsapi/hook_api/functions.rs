//! js_hook, js_unhook, js_call_native implementations

use crate::ffi;
use crate::ffi::hook as hook_ffi;
use crate::jsapi::ptr::get_native_pointer_addr;
use crate::jsapi::util::is_addr_accessible;
use crate::value::JSValue;

use super::callback::hook_callback_wrapper;
use super::registry::{hook_error_message, init_registry, HookData, HOOK_OK, HOOK_REGISTRY};

/// hook(ptr, callback, stealth?) - Install a hook at the given address
/// stealth: optional boolean, default false. If true, uses wxshadow for traceless hooking.
pub(crate) unsafe extern "C" fn js_hook(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 2 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"hook() requires at least 2 arguments\0".as_ptr() as *const _,
        );
    }

    let ptr_arg = JSValue(*argv);
    let callback_arg = JSValue(*argv.add(1));

    // Get optional stealth flag (3rd argument, default false)
    let stealth = if argc >= 3 {
        let stealth_arg = JSValue(*argv.add(2));
        stealth_arg.to_bool().unwrap_or(false)
    } else {
        false
    };

    // Get the address
    let addr = match get_native_pointer_addr(ctx, ptr_arg) {
        Some(a) => a,
        None => {
            // Try to convert directly
            match ptr_arg.to_u64(ctx) {
                Some(a) => a,
                None => {
                    return ffi::JS_ThrowTypeError(
                        ctx,
                        b"hook() first argument must be a pointer\0".as_ptr() as *const _,
                    )
                }
            }
        }
    };

    // Check callback is a function
    if !callback_arg.is_function(ctx) {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"hook() second argument must be a function\0".as_ptr() as *const _,
        );
    }

    // Initialize registry
    init_registry();

    // Duplicate the callback to prevent GC
    let callback_dup = ffi::qjs_dup_value(ctx, callback_arg.raw());

    // Store in registry - convert to bytes for Send/Sync safety
    let mut callback_bytes = [0u8; 16];
    std::ptr::copy_nonoverlapping(
        &callback_dup as *const ffi::JSValue as *const u8,
        callback_bytes.as_mut_ptr(),
        16,
    );

    {
        let mut guard = HOOK_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
        let registry = guard.as_mut().unwrap();
        registry.insert(
            addr,
            HookData {
                ctx: ctx as usize,
                callback_bytes,
            },
        );
    }

    // Install the hook
    let result = hook_ffi::hook_attach(
        addr as *mut std::ffi::c_void,
        Some(hook_callback_wrapper),
        None,                          // No on_leave callback for now
        addr as *mut std::ffi::c_void, // Use address as user_data to look up callback
        if stealth { 1 } else { 0 },
    );

    if result != HOOK_OK {
        // Failed - cleanup
        let mut guard = HOOK_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(registry) = guard.as_mut() {
            if let Some(data) = registry.remove(&addr) {
                let callback: ffi::JSValue =
                    std::ptr::read(data.callback_bytes.as_ptr() as *const ffi::JSValue);
                ffi::qjs_free_value(ctx, callback);
            }
        }
        let err_msg = hook_error_message(result);
        return ffi::JS_ThrowInternalError(ctx, err_msg.as_ptr() as *const _);
    }

    JSValue::bool(true).raw()
}

/// unhook(ptr) - Remove a hook at the given address
pub(crate) unsafe extern "C" fn js_unhook(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(ctx, b"unhook() requires 1 argument\0".as_ptr() as *const _);
    }

    let ptr_arg = JSValue(*argv);

    // Get the address
    let addr = match get_native_pointer_addr(ctx, ptr_arg) {
        Some(a) => a,
        None => match ptr_arg.to_u64(ctx) {
            Some(a) => a,
            None => {
                return ffi::JS_ThrowTypeError(
                    ctx,
                    b"unhook() argument must be a pointer\0".as_ptr() as *const _,
                )
            }
        },
    };

    // Remove from registry and free callback
    {
        let mut guard = HOOK_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(registry) = guard.as_mut() {
            if let Some(data) = registry.remove(&addr) {
                let ctx = data.ctx as *mut ffi::JSContext;
                let callback: ffi::JSValue =
                    std::ptr::read(data.callback_bytes.as_ptr() as *const ffi::JSValue);
                ffi::qjs_free_value(ctx, callback);
            }
        }
    }

    // Remove the hook
    let result = hook_ffi::hook_remove(addr as *mut std::ffi::c_void);

    if result != HOOK_OK {
        let err_msg = hook_error_message(result);
        return ffi::JS_ThrowInternalError(ctx, err_msg.as_ptr() as *const _);
    }

    JSValue::bool(true).raw()
}

/// callNative(ptr, arg0?, arg1?, ..., arg5?) - Call a native function at addr with 0-6 args.
/// Arguments are passed in x0-x5 (ARM64 calling convention). Unspecified args default to 0.
/// Return value: Number when result fits exactly in f64 (≤ 2^53), BigUint64 otherwise.
pub(crate) unsafe extern "C" fn js_call_native(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"callNative() requires at least 1 argument\0".as_ptr() as *const _,
        );
    }

    let ptr_arg = JSValue(*argv);

    let addr = match get_native_pointer_addr(ctx, ptr_arg) {
        Some(a) => a,
        None => match ptr_arg.to_u64(ctx) {
            Some(a) => a,
            None => {
                return ffi::JS_ThrowTypeError(
                    ctx,
                    b"callNative() argument must be a pointer or number\0".as_ptr() as *const _,
                )
            }
        },
    };

    // Reject null and near-zero addresses without calling mincore:
    // the first 64KB is never a valid user-space function pointer on ARM64 Android.
    if addr < 0x10000 {
        return ffi::JS_ThrowRangeError(
            ctx,
            b"callNative() address is not mapped\0".as_ptr() as *const _,
        );
    }

    // For higher addresses, verify accessibility via mincore before calling.
    if !is_addr_accessible(addr, 4) {
        return ffi::JS_ThrowRangeError(
            ctx,
            b"callNative() address is not mapped\0".as_ptr() as *const _,
        );
    }

    // Extract up to 6 integer/pointer arguments (argv[1..6]), passed via x0-x5.
    // Unspecified arguments default to 0.
    let mut args = [0u64; 6];
    for i in 0..6usize {
        if (i + 1) < argc as usize {
            let arg = JSValue(*argv.add(i + 1));
            if let Some(v) = arg.to_u64(ctx) {
                args[i] = v;
            }
            // If conversion fails (e.g. non-numeric arg), keep default 0
        }
    }

    let func: unsafe extern "C" fn(u64, u64, u64, u64, u64, u64) -> i64 =
        std::mem::transmute(addr as usize);
    let result = func(args[0], args[1], args[2], args[3], args[4], args[5]);

    // Return Number when the result magnitude fits exactly as f64 (≤ 2^53).
    // Use unsigned_abs() so negative i64 results (e.g. errno -1) are also returned
    // as JS Number instead of wrapping to a huge BigInt.
    // JS_NewInt64 encodes small integers as JS_TAG_INT (typeof === "number").
    if result.unsigned_abs() <= (1u64 << 53) {
        ffi::qjs_new_int64(ctx, result)
    } else {
        ffi::JS_NewBigInt64(ctx, result)
    }
}
