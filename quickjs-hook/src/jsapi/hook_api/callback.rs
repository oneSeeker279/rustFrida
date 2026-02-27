//! Hook callback wrapper (cross-thread safety, context building)

use crate::ffi;
use crate::ffi::hook as hook_ffi;
use crate::jsapi::console::output_message;
use crate::value::JSValue;
use std::ffi::CString;

use super::registry::HOOK_REGISTRY;

/// Hook callback that calls the JS function
pub(crate) unsafe extern "C" fn hook_callback_wrapper(
    ctx_ptr: *mut hook_ffi::HookContext,
    user_data: *mut std::ffi::c_void,
) {
    if ctx_ptr.is_null() || user_data.is_null() {
        return;
    }

    let target_addr = user_data as u64;

    // Copy callback data then release the lock before QuickJS operations.
    // Holding the registry lock during JS_Call risks deadlock if the JS callback
    // itself tries to hook/unhook. Also avoids holding a lock during potentially
    // blocking QuickJS execution.
    let (ctx_usize, callback_bytes) = {
        let guard = match HOOK_REGISTRY.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        let registry = match guard.as_ref() {
            Some(r) => r,
            None => return,
        };
        let hook_data = match registry.get(&target_addr) {
            Some(d) => d,
            None => return,
        };
        (hook_data.ctx, hook_data.callback_bytes)
    }; // HOOK_REGISTRY lock released here

    // Serialize concurrent JS_Call invocations from multiple hooked threads.
    // QuickJS is not thread-safe; without this lock, two threads hitting the same
    // hook simultaneously would corrupt the runtime state.
    //
    // Use try_lock() to prevent same-thread deadlock: if the hooked function is
    // called from within load_script() (which already holds JS_ENGINE), a blocking
    // lock() would deadlock because std::sync::Mutex is not reentrant. try_lock()
    // returns WouldBlock in that case and we skip the callback safely.
    let _js_guard = match crate::JS_ENGINE.try_lock() {
        Ok(g) => g,
        Err(std::sync::TryLockError::WouldBlock) => {
            // Same thread already holds JS_ENGINE (re-entrant call) or another
            // thread is mid-callback. Skip this invocation to avoid deadlock.
            return;
        }
        Err(std::sync::TryLockError::Poisoned(e)) => e.into_inner(),
    };

    let ctx = ctx_usize as *mut ffi::JSContext;
    // Reconstruct JSValue from bytes
    let callback: ffi::JSValue =
        std::ptr::read(callback_bytes.as_ptr() as *const ffi::JSValue);

    // CRITICAL: Update QuickJS stack top before ANY QuickJS operations.
    // This hook callback fires in the hooked thread's context, which has a
    // different stack than the JS-init thread. Without this call, QuickJS's
    // stack-overflow check compares the current SP against the JS thread's
    // stack_top, sees a huge difference, falsely detects overflow, tries to
    // throw an exception, recurses, and crashes with SIGSEGV.
    ffi::qjs_update_stack_top(ctx);

    // Create context object for JS callback
    let js_ctx = ffi::JS_NewObject(ctx);

    // Populate context with register values
    let hook_ctx = &*ctx_ptr;

    // Add x0-x30
    for i in 0..31 {
        let prop_name = format!("x{}", i);
        let cprop = CString::new(prop_name).unwrap();
        let atom = ffi::JS_NewAtom(ctx, cprop.as_ptr());
        let val = ffi::JS_NewBigUint64(ctx, hook_ctx.x[i]);
        ffi::qjs_set_property(ctx, js_ctx, atom, val);
        ffi::JS_FreeAtom(ctx, atom);
    }

    // Add sp
    {
        let cprop = CString::new("sp").unwrap();
        let atom = ffi::JS_NewAtom(ctx, cprop.as_ptr());
        let val = ffi::JS_NewBigUint64(ctx, hook_ctx.sp);
        ffi::qjs_set_property(ctx, js_ctx, atom, val);
        ffi::JS_FreeAtom(ctx, atom);
    }

    // Add pc
    {
        let cprop = CString::new("pc").unwrap();
        let atom = ffi::JS_NewAtom(ctx, cprop.as_ptr());
        let val = ffi::JS_NewBigUint64(ctx, hook_ctx.pc);
        ffi::qjs_set_property(ctx, js_ctx, atom, val);
        ffi::JS_FreeAtom(ctx, atom);
    }

    let global = ffi::JS_GetGlobalObject(ctx);
    let result = ffi::JS_Call(ctx, callback, global, 1, &js_ctx as *const _ as *mut _);

    // Check for JS exception thrown by the callback.
    // If the callback threw, report the error and skip register write-back.
    if ffi::qjs_is_exception(result) != 0 {
        let exc = ffi::JS_GetException(ctx);
        let exc_val = JSValue(exc);
        // Use .message property directly (avoids calling toString() which may itself throw
        // and return NULL from JS_ToCString, silencing the error message entirely).
        let msg_prop = exc_val.get_property(ctx, "message");
        let msg = if let Some(s) = msg_prop.to_string(ctx) {
            msg_prop.free(ctx);
            s
        } else {
            msg_prop.free(ctx);
            exc_val.to_string(ctx).unwrap_or_else(|| "[unknown exception]".to_string())
        };
        output_message(&format!("[hook error] {}", msg));
        exc_val.free(ctx);
        // JS_EXCEPTION sentinel does not own heap memory; qjs_free_value is a no-op for it.
        ffi::qjs_free_value(ctx, js_ctx);
        ffi::qjs_free_value(ctx, result);
        ffi::qjs_free_value(ctx, global);
        return;
    }

    // Check if callback modified any registers
    // Read back x0-x7 (commonly modified)
    for i in 0..8 {
        let prop_name = format!("x{}", i);
        let cprop = CString::new(prop_name).unwrap();
        let atom = ffi::JS_NewAtom(ctx, cprop.as_ptr());
        let val = ffi::qjs_get_property(ctx, js_ctx, atom);
        ffi::JS_FreeAtom(ctx, atom);

        let js_val = JSValue(val);
        if let Some(new_val) = js_val.to_u64(ctx) {
            (*ctx_ptr).x[i] = new_val;
        }
        js_val.free(ctx);
    }

    // Cleanup
    ffi::qjs_free_value(ctx, js_ctx);
    ffi::qjs_free_value(ctx, result);
    ffi::qjs_free_value(ctx, global);
}
