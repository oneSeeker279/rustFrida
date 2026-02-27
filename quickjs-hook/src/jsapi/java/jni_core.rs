//! JNI core types, constants, and initialization
//!
//! Contains: ArtMethod layout constants, JNI type aliases, function table helpers,
//! entry_point offset probing, JNI state management.

use crate::jsapi::console::output_message;
use std::ffi::CString;
use std::os::raw::c_char;
use std::sync::Mutex;

// ============================================================================
// ArtMethod layout constants (ARM64 Android 8+)
// ============================================================================

/// Offset of access_flags_ in ArtMethod
pub(super) const ART_METHOD_ACCESS_FLAGS_OFFSET: usize = 4;

/// Offset of data_ (native function pointer for native methods) in ArtMethod
pub(super) const ART_METHOD_DATA_OFFSET: usize = 16;

/// kAccNative — marks method as native (ART uses JNI trampoline to call data_)
pub(super) const K_ACC_NATIVE: u32 = 0x0100;
/// kAccCompileDontBother — prevents JIT from recompiling the method
pub(super) const K_ACC_COMPILE_DONT_BOTHER: u32 = 1 << 25;
/// kAccPreCompiled — marks method as pre-compiled (Frida sets this)
pub(super) const K_ACC_PRE_COMPILED: u32 = 1 << 24;
/// kAccFastInterpreterToInterpreterInvoke — fast interpreter dispatch (must clear for native)
pub(super) const K_ACC_FAST_INTERP_TO_INTERP: u32 = 1 << 30;
/// kAccSingleImplementation — devirtualization optimization (must clear for hooked methods)
pub(super) const K_ACC_SINGLE_IMPLEMENTATION: u32 = 1 << 28;
/// kAccFastNative — fast JNI (@FastNative annotation, must clear for our hook)
pub(super) const K_ACC_FAST_NATIVE: u32 = 0x00080000;
/// kAccCriticalNative — critical JNI (@CriticalNative, must clear)
pub(super) const K_ACC_CRITICAL_NATIVE: u32 = 0x00200000;
/// kAccSkipAccessChecks — skip access checks optimization (must clear)
pub(super) const K_ACC_SKIP_ACCESS_CHECKS: u32 = 1 << 18;
/// kAccNterpEntryPointFastPath — nterp fast path (must clear for native conversion)
pub(super) const K_ACC_NTERP_ENTRY_POINT_FAST_PATH: u32 = 1 << 22;

/// Cached entry_point offset, determined at runtime.
/// Android 12 emulator uses 24 (no separate data_ field, 32-byte ArtMethod).
/// Standard AOSP uses 32 (data_ at 24, 40-byte ArtMethod).
pub(super) static ENTRY_POINT_OFFSET: std::sync::OnceLock<usize> = std::sync::OnceLock::new();

// ============================================================================
// JNI type aliases + helpers (module-level, shared across all functions)
// ============================================================================

pub(super) type JniEnv = *mut *const *const std::ffi::c_void;

pub(super) type FindClassFn = unsafe extern "C" fn(JniEnv, *const c_char) -> *mut std::ffi::c_void;
pub(super) type GetMethodIdFn = unsafe extern "C" fn(
    JniEnv, *mut std::ffi::c_void, *const c_char, *const c_char,
) -> *mut std::ffi::c_void;
pub(super) type GetStaticMethodIdFn = unsafe extern "C" fn(
    JniEnv, *mut std::ffi::c_void, *const c_char, *const c_char,
) -> *mut std::ffi::c_void;
pub(super) type ExcCheckFn = unsafe extern "C" fn(JniEnv) -> u8;
pub(super) type ExcClearFn = unsafe extern "C" fn(JniEnv);
pub(super) type DeleteLocalRefFn = unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void);
pub(super) type NewLocalRefFn = unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void) -> *mut std::ffi::c_void;
pub(super) type NewGlobalRefFn = unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void) -> *mut std::ffi::c_void;
pub(super) type DeleteGlobalRefFn = unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void);
pub(super) type GetFieldIdFn = unsafe extern "C" fn(
    JniEnv, *mut std::ffi::c_void, *const c_char, *const c_char,
) -> *mut std::ffi::c_void;
pub(super) type NewStringUtfFn = unsafe extern "C" fn(JniEnv, *const c_char) -> *mut std::ffi::c_void;
pub(super) type GetStringUtfCharsFn = unsafe extern "C" fn(
    JniEnv, *mut std::ffi::c_void, *mut u8,
) -> *const c_char;
pub(super) type ReleaseStringUtfCharsFn = unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *const c_char);
pub(super) type PushLocalFrameFn = unsafe extern "C" fn(JniEnv, i32) -> i32;
pub(super) type PopLocalFrameFn = unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void) -> *mut std::ffi::c_void;
pub(super) type GetArrayLengthFn = unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void) -> i32;
pub(super) type GetObjectArrayElementFn = unsafe extern "C" fn(
    JniEnv, *mut std::ffi::c_void, i32,
) -> *mut std::ffi::c_void;
pub(super) type CallObjectMethodAFn = unsafe extern "C" fn(
    JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, *const std::ffi::c_void,
) -> *mut std::ffi::c_void;
pub(super) type CallStaticObjectMethodAFn = unsafe extern "C" fn(
    JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, *const std::ffi::c_void,
) -> *mut std::ffi::c_void;
pub(super) type CallIntMethodAFn = unsafe extern "C" fn(
    JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, *const std::ffi::c_void,
) -> i32;
pub(super) type ToReflectedMethodFn = unsafe extern "C" fn(
    JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, u8,
) -> *mut std::ffi::c_void;
pub(super) type GetLongFieldFn = unsafe extern "C" fn(
    JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void,
) -> i64;
pub(super) type GetBooleanFieldFn = unsafe extern "C" fn(
    JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void,
) -> u8;
pub(super) type GetByteFieldFn = unsafe extern "C" fn(
    JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void,
) -> i8;
pub(super) type GetCharFieldFn = unsafe extern "C" fn(
    JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void,
) -> u16;
pub(super) type GetShortFieldFn = unsafe extern "C" fn(
    JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void,
) -> i16;
pub(super) type GetIntFieldFn = unsafe extern "C" fn(
    JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void,
) -> i32;
pub(super) type GetFloatFieldFn = unsafe extern "C" fn(
    JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void,
) -> f32;
pub(super) type GetDoubleFieldFn = unsafe extern "C" fn(
    JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void,
) -> f64;
pub(super) type GetObjectFieldFn = unsafe extern "C" fn(
    JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void,
) -> *mut std::ffi::c_void;

/// Call a JNI function from the function table by index.
/// JNIEnv is `JNINativeInterface**` — (*env)[index] is the function pointer.
#[inline]
pub(crate) unsafe fn jni_fn_ptr(env: JniEnv, index: usize) -> *const std::ffi::c_void {
    let table = *env as *const *const std::ffi::c_void;
    *table.add(index)
}

/// Check for and clear any pending JNI exception. Returns true if there was one.
#[inline]
pub(super) unsafe fn jni_check_exc(env: JniEnv) -> bool {
    let check: ExcCheckFn = jni_fn!(env, ExcCheckFn, JNI_EXCEPTION_CHECK);
    if check(env) != 0 {
        let clear: ExcClearFn = jni_fn!(env, ExcClearFn, JNI_EXCEPTION_CLEAR);
        clear(env);
        true
    } else {
        false
    }
}

/// Check if a 64-bit value looks like a valid ARM64 code pointer.
/// Valid user-space code pointers on ARM64 Android have:
/// - Bits 48-63 all zero (canonical lower-half address)
/// - Non-zero value (not null)
/// - dladdr resolves it (it's in a mapped executable region)
pub(super) fn is_code_pointer(val: u64) -> bool {
    if val == 0 {
        return false;
    }
    // Check canonical form: bits 48-63 must be 0 for user-space
    if (val >> 48) != 0 {
        return false;
    }
    // Verify it resolves via dladdr (mapped executable memory)
    unsafe {
        let mut info: libc::Dl_info = std::mem::zeroed();
        libc::dladdr(val as *const std::ffi::c_void, &mut info) != 0
    }
}

/// Get Android API level from system property ro.build.version.sdk.
pub(super) fn get_android_api_level() -> i32 {
    let prop = CString::new("ro.build.version.sdk").unwrap();
    let mut buf = [0u8; 32];
    // __system_property_get is always available on Android
    unsafe {
        let get_prop: unsafe extern "C" fn(*const c_char, *mut c_char) -> i32 =
            std::mem::transmute(libc::dlsym(
                libc::RTLD_DEFAULT,
                b"__system_property_get\0".as_ptr() as *const _,
            ));
        get_prop(prop.as_ptr(), buf.as_mut_ptr() as *mut c_char);
    }
    let s = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr() as *const c_char) };
    s.to_str().unwrap_or("0").parse().unwrap_or(0)
}

/// Determine the entry_point_from_quick_compiled_code_ offset by probing.
///
/// Strategy: read values at both candidate offsets (24 and 32) from a known method.
/// The entry_point is the one that looks like a valid code pointer (canonical 48-bit VA
/// resolvable by dladdr). The other offset is either data_ or the next ArtMethod.
fn probe_entry_point_offset(env: JniEnv, target_art_method: u64) -> usize {
    // Read candidate values at offset 24 and 32
    let val_24 = unsafe { *((target_art_method as usize + 24) as *const u64) };
    let val_32 = unsafe { *((target_art_method as usize + 32) as *const u64) };

    let is_24 = is_code_pointer(val_24);
    let is_32 = is_code_pointer(val_32);

    output_message(&format!(
        "[java hook] probe: val_24={:#x} (code={}), val_32={:#x} (code={})",
        val_24, is_24, val_32, is_32
    ));

    let offset = if is_24 && !is_32 {
        24 // Only offset 24 is a code pointer → 32-byte ArtMethod
    } else if is_32 && !is_24 {
        32 // Only offset 32 is a code pointer → 40-byte ArtMethod
    } else if is_24 && is_32 {
        // Both look like code pointers — use stride detection as tiebreaker
        let cur_dex_idx = unsafe { *((target_art_method as usize + 12) as *const u32) };
        let next_32 = unsafe { *((target_art_method as usize + 32 + 12) as *const u32) };
        if next_32 == cur_dex_idx + 1 {
            24 // stride 32 confirmed → entry_point at 24
        } else {
            32 // assume 40-byte ArtMethod
        }
    } else {
        // Neither looks valid — try a secondary probe with Object.hashCode
        probe_with_known_method(env).unwrap_or(24) // default to 24 (Android 12+)
    };

    output_message(&format!(
        "[java hook] ArtMethod entry_point offset={}", offset,
    ));

    offset
}

/// Secondary probe using Object.hashCode() — a well-known non-native method
/// that should have a valid entry_point.
fn probe_with_known_method(env: JniEnv) -> Option<usize> {
    unsafe {
        let c_class = CString::new("java/lang/Object").unwrap();
        let c_method = CString::new("hashCode").unwrap();
        let c_sig = CString::new("()I").unwrap();

        let find_class: FindClassFn = jni_fn!(env, FindClassFn, JNI_FIND_CLASS);
        let get_mid: GetMethodIdFn = jni_fn!(env, GetMethodIdFn, JNI_GET_METHOD_ID);
        let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);

        let cls = find_class(env, c_class.as_ptr());
        if cls.is_null() || jni_check_exc(env) {
            return None;
        }

        let mid = get_mid(env, cls, c_method.as_ptr(), c_sig.as_ptr());
        delete_local_ref(env, cls);
        if mid.is_null() || jni_check_exc(env) {
            return None;
        }

        let am = mid as u64;
        let v24 = *((am as usize + 24) as *const u64);
        let v32 = *((am as usize + 32) as *const u64);
        let c24 = is_code_pointer(v24);
        let c32 = is_code_pointer(v32);

        output_message(&format!(
            "[java hook] secondary probe (Object.hashCode): val_24={:#x} (code={}), val_32={:#x} (code={})",
            v24, c24, v32, c32
        ));

        if c24 && !c32 { Some(24) }
        else if c32 && !c24 { Some(32) }
        else { None }
    }
}

/// Get the entry_point offset, probing on first use
pub(super) fn get_entry_point_offset(env: JniEnv, art_method: u64) -> usize {
    *ENTRY_POINT_OFFSET.get_or_init(|| probe_entry_point_offset(env, art_method))
}

// ============================================================================
// JNI function table indices (stable across Android versions)
// ============================================================================

pub(super) const JNI_FIND_CLASS: usize = 6;
pub(super) const JNI_TO_REFLECTED_METHOD: usize = 9;
pub(super) const JNI_EXCEPTION_CLEAR: usize = 17;
pub(super) const JNI_PUSH_LOCAL_FRAME: usize = 19;
pub(super) const JNI_POP_LOCAL_FRAME: usize = 20;
pub(super) const JNI_DELETE_LOCAL_REF: usize = 23;
pub(super) const JNI_GET_METHOD_ID: usize = 33;
pub(super) const JNI_CALL_OBJECT_METHOD_A: usize = 36;
pub(super) const JNI_CALL_INT_METHOD_A: usize = 51;
pub(super) const JNI_GET_STATIC_METHOD_ID: usize = 113;
pub(super) const JNI_GET_STRING_UTF_CHARS: usize = 169;
pub(super) const JNI_RELEASE_STRING_UTF_CHARS: usize = 170;
pub(super) const JNI_GET_ARRAY_LENGTH: usize = 171;
pub(super) const JNI_GET_OBJECT_ARRAY_ELEMENT: usize = 173;
pub(super) const JNI_EXCEPTION_CHECK: usize = 228;

pub(super) const JNI_CALL_STATIC_OBJECT_METHOD_A: usize = 116;
pub(super) const JNI_NEW_STRING_UTF: usize = 167;

// CallNonvirtual*MethodA indices (for callOriginal on instance methods)
pub(super) const JNI_CALL_NONVIRTUAL_OBJECT_METHOD_A: usize = 66;
pub(super) const JNI_CALL_NONVIRTUAL_BOOLEAN_METHOD_A: usize = 69;
pub(super) const JNI_CALL_NONVIRTUAL_INT_METHOD_A: usize = 81;
pub(super) const JNI_CALL_NONVIRTUAL_LONG_METHOD_A: usize = 84;
pub(super) const JNI_CALL_NONVIRTUAL_VOID_METHOD_A: usize = 93;

// CallStatic*MethodA indices (for callOriginal on static methods)
pub(super) const JNI_CALL_STATIC_VOID_METHOD_A: usize = 143;
pub(super) const JNI_CALL_STATIC_BOOLEAN_METHOD_A: usize = 119;
pub(super) const JNI_CALL_STATIC_INT_METHOD_A: usize = 131;
pub(super) const JNI_CALL_STATIC_LONG_METHOD_A: usize = 134;

// Ref management
pub(super) const JNI_DELETE_GLOBAL_REF: usize = 22;

// Field access & reflection
pub(super) const JNI_IS_INSTANCE_OF: usize = 32;
pub(super) const JNI_NEW_GLOBAL_REF: usize = 21;
pub(super) const JNI_NEW_LOCAL_REF: usize = 25;
pub(super) const JNI_GET_FIELD_ID: usize = 94;
pub(super) const JNI_GET_OBJECT_FIELD: usize = 95;
pub(super) const JNI_GET_BOOLEAN_FIELD: usize = 96;
pub(super) const JNI_GET_BYTE_FIELD: usize = 97;
pub(super) const JNI_GET_CHAR_FIELD: usize = 98;
pub(super) const JNI_GET_SHORT_FIELD: usize = 99;
pub(super) const JNI_GET_INT_FIELD: usize = 100;
pub(super) const JNI_GET_LONG_FIELD: usize = 101;
pub(super) const JNI_GET_FLOAT_FIELD: usize = 102;
pub(super) const JNI_GET_DOUBLE_FIELD: usize = 103;

// ============================================================================
// JNI state (lazy-initialized, cached)
// ============================================================================

pub(super) struct JniState {
    pub(super) env: JniEnv,               // JNIEnv*
    pub(super) vm: *mut std::ffi::c_void, // JavaVM*
}

unsafe impl Send for JniState {}
unsafe impl Sync for JniState {}

pub(super) static JNI_STATE: Mutex<Option<JniState>> = Mutex::new(None);

/// Initialize JNI state by finding the existing JavaVM in the target process.
pub(super) fn ensure_jni_initialized() -> Result<JniEnv, String> {
    let mut guard = JNI_STATE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(ref state) = *guard {
        return Ok(state.env);
    }

    unsafe {
        // Find JNI_GetCreatedJavaVMs — try RTLD_DEFAULT first, then explicit dlopen
        let sym_name = CString::new("JNI_GetCreatedJavaVMs").unwrap();
        let mut sym = libc::dlsym(libc::RTLD_DEFAULT, sym_name.as_ptr());
        if sym.is_null() {
            // PROTECTED visibility on Android — need explicit dlopen
            for lib in &["libart.so", "libnativehelper.so"] {
                let lib_name = CString::new(*lib).unwrap();
                let handle = libc::dlopen(lib_name.as_ptr(), libc::RTLD_NOW | libc::RTLD_NOLOAD);
                if !handle.is_null() {
                    sym = libc::dlsym(handle, sym_name.as_ptr());
                    if !sym.is_null() { break; }
                }
            }
        }
        if sym.is_null() {
            return Err("dlsym(JNI_GetCreatedJavaVMs) failed".to_string());
        }

        // JNI_GetCreatedJavaVMs(JavaVM** vmBuf, jsize bufLen, jsize* nVMs) -> jint
        let get_vms: unsafe extern "C" fn(
            *mut *mut std::ffi::c_void, // JavaVM**
            i32,
            *mut i32,
        ) -> i32 = std::mem::transmute(sym);

        let mut vm_ptr: *mut std::ffi::c_void = std::ptr::null_mut();
        let mut vm_count: i32 = 0;
        let ret = get_vms(&mut vm_ptr, 1, &mut vm_count);
        if ret != 0 || vm_count == 0 || vm_ptr.is_null() {
            return Err("JNI_GetCreatedJavaVMs failed".to_string());
        }

        // JavaVM is JNIInvokeInterface** — (*vm)[index] is the function pointer
        // AttachCurrentThread is at index 4 (GetEnv=6, but AttachCurrentThread=4)
        let vm_table = *(vm_ptr as *const *const *const std::ffi::c_void);
        let attach_fn: unsafe extern "C" fn(
            *mut std::ffi::c_void, // JavaVM*
            *mut *mut std::ffi::c_void, // JNIEnv**
            *mut std::ffi::c_void, // args (NULL)
        ) -> i32 = std::mem::transmute(*vm_table.add(4));

        let mut env_ptr: *mut std::ffi::c_void = std::ptr::null_mut();
        let ret = attach_fn(vm_ptr, &mut env_ptr, std::ptr::null_mut());
        if ret != 0 || env_ptr.is_null() {
            return Err("AttachCurrentThread failed".to_string());
        }

        let env: JniEnv = env_ptr as JniEnv;
        *guard = Some(JniState { env, vm: vm_ptr });
        Ok(env)
    }
}

/// Get a valid JNIEnv* for the current thread via AttachCurrentThread.
/// Safe to call from any thread (hook callbacks run on the hooked thread).
/// AttachCurrentThread is idempotent — returns existing env if already attached.
pub(super) unsafe fn get_thread_env() -> Result<JniEnv, String> {
    let _ = ensure_jni_initialized()?;
    let vm_ptr = {
        let guard = JNI_STATE.lock().unwrap_or_else(|e| e.into_inner());
        match guard.as_ref() {
            Some(state) => state.vm,
            None => return Err("JNI not initialized".to_string()),
        }
    };

    let vm_table = *(vm_ptr as *const *const *const std::ffi::c_void);
    let attach_fn: unsafe extern "C" fn(
        *mut std::ffi::c_void,
        *mut *mut std::ffi::c_void,
        *mut std::ffi::c_void,
    ) -> i32 = std::mem::transmute(*vm_table.add(4));

    let mut env_ptr: *mut std::ffi::c_void = std::ptr::null_mut();
    let ret = attach_fn(vm_ptr, &mut env_ptr, std::ptr::null_mut());
    if ret != 0 || env_ptr.is_null() {
        return Err("AttachCurrentThread failed".to_string());
    }

    Ok(env_ptr as JniEnv)
}
