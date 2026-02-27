//! ArtMethod resolution, entry_point access, JNI trampoline discovery, field cache
//!
//! Contains: resolve_art_method, read_entry_point, set_native_hook_flags,
//! find_jni_trampoline, CachedFieldInfo, FIELD_CACHE, cache_fields_for_class.

use crate::jsapi::console::output_message;
use std::collections::HashMap;
use std::ffi::CString;
use std::os::raw::c_char;
use std::sync::Mutex;

use super::jni_core::*;
use super::reflect::*;

// ============================================================================
// ArtMethod resolution
// ============================================================================

/// Resolve a Java method to its ArtMethod* address.
/// Returns (art_method_ptr, is_static).
/// When `force_static` is true, skips GetMethodID and goes straight to GetStaticMethodID.
pub(super) fn resolve_art_method(
    env: JniEnv,
    class_name: &str,
    method_name: &str,
    signature: &str,
    force_static: bool,
) -> Result<(u64, bool), String> {
    let c_method = CString::new(method_name).map_err(|_| "invalid method name")?;
    let c_sig = CString::new(signature).map_err(|_| "invalid signature")?;

    unsafe {
        let cls = find_class_safe(env, class_name);

        if cls.is_null() {
            return Err(format!("FindClass('{}') failed", class_name));
        }

        let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);

        // Try GetMethodID (instance method first), unless force_static
        if !force_static {
            let get_method_id: GetMethodIdFn = jni_fn!(env, GetMethodIdFn, JNI_GET_METHOD_ID);

            let method_id = get_method_id(env, cls, c_method.as_ptr(), c_sig.as_ptr());
            output_message(&format!(
                "[resolve_art_method] cls={:#x}, GetMethodID({}.{}{})={:#x}",
                cls as u64, class_name, method_name, signature, method_id as u64
            ));

            if !method_id.is_null() && !jni_check_exc(env) {
                // Decode BEFORE deleting cls (ToReflectedMethod needs cls)
                let art_method = decode_method_id(env, cls, method_id as u64, false);
                delete_local_ref(env, cls);
                return Ok((art_method, false));
            }

            // Clear exception from GetMethodID failure
            jni_check_exc(env);
        }

        // Try GetStaticMethodID
        let get_static_method_id: GetStaticMethodIdFn = jni_fn!(env, GetStaticMethodIdFn, JNI_GET_STATIC_METHOD_ID);

        let method_id = get_static_method_id(env, cls, c_method.as_ptr(), c_sig.as_ptr());

        if !method_id.is_null() && !jni_check_exc(env) {
            // Decode BEFORE deleting cls (ToReflectedMethod needs cls)
            let art_method = decode_method_id(env, cls, method_id as u64, true);
            delete_local_ref(env, cls);
            return Ok((art_method, true));
        }

        jni_check_exc(env);

        // Cleanup
        delete_local_ref(env, cls);

        Err(format!(
            "method not found: {}.{}{}",
            class_name, method_name, signature
        ))
    }
}

/// Read the entry_point_from_quick_compiled_code_ from ArtMethod
pub(super) unsafe fn read_entry_point(art_method: u64, offset: usize) -> u64 {
    let ptr = (art_method as usize + offset) as *const u64;
    std::ptr::read_volatile(ptr)
}

/// Modify ArtMethod access_flags_ for native hook conversion.
/// Sets kAccNative, kAccCompileDontBother, kAccPreCompiled.
/// Clears flags incompatible with our native hook trampoline.
pub(super) unsafe fn set_native_hook_flags(art_method: u64) {
    let ptr = (art_method as usize + ART_METHOD_ACCESS_FLAGS_OFFSET) as *mut u32;
    let flags = std::ptr::read_volatile(ptr);
    let new_flags = (flags | K_ACC_NATIVE | K_ACC_COMPILE_DONT_BOTHER | K_ACC_PRE_COMPILED)
        & !(K_ACC_FAST_INTERP_TO_INTERP
            | K_ACC_SINGLE_IMPLEMENTATION
            | K_ACC_FAST_NATIVE
            | K_ACC_CRITICAL_NATIVE
            | K_ACC_SKIP_ACCESS_CHECKS
            | K_ACC_NTERP_ENTRY_POINT_FAST_PATH);
    std::ptr::write_volatile(ptr, new_flags);
}

/// Cached generic JNI trampoline address (art_quick_generic_jni_trampoline).
static JNI_TRAMPOLINE: std::sync::OnceLock<u64> = std::sync::OnceLock::new();

/// Find art_quick_generic_jni_trampoline using Frida java-bridge approach.
///
/// Strategy (same as Frida):
///   1. Try dlsym (works on some Android builds)
///   2. Read from ART ClassLinker struct:
///      JavaVM* → JavaVMExt.runtime_ → Runtime.classLinker_ → ClassLinker.quickGenericJniTrampoline
///      Uses InternTable as anchor to find the exact offset within ClassLinker.
///
/// Returns 0 if all strategies fail.
pub(super) unsafe fn find_jni_trampoline(_env: JniEnv, _ep_offset: usize) -> u64 {
    *JNI_TRAMPOLINE.get_or_init(|| {
        // --- Strategy 1: dlsym ---
        let sym_name = CString::new("art_quick_generic_jni_trampoline").unwrap();

        let sym = libc::dlsym(libc::RTLD_DEFAULT, sym_name.as_ptr());
        if !sym.is_null() {
            output_message(&format!(
                "[java hook] JNI trampoline from dlsym(DEFAULT): {:#x}", sym as u64
            ));
            return sym as u64;
        }

        let lib = CString::new("libart.so").unwrap();
        let handle = libc::dlopen(lib.as_ptr(), libc::RTLD_NOW | libc::RTLD_NOLOAD);
        if !handle.is_null() {
            let sym = libc::dlsym(handle, sym_name.as_ptr());
            if !sym.is_null() {
                output_message(&format!(
                    "[java hook] JNI trampoline from dlsym(libart.so): {:#x}", sym as u64
                ));
                return sym as u64;
            }
        }

        // --- Strategy 2: Frida-style ClassLinker scan ---
        // JavaVMExt layout: { JNIInvokeInterface* functions; Runtime* runtime_; ... }
        // So runtime_ is at offset 8 on ARM64.
        output_message("[java hook] dlsym failed, trying ClassLinker scan (Frida approach)...");

        let vm_ptr = {
            let guard = JNI_STATE.lock().unwrap_or_else(|e| e.into_inner());
            match guard.as_ref() {
                Some(state) => state.vm,
                None => {
                    output_message("[java hook] ClassLinker scan: no JavaVM cached");
                    return 0;
                }
            }
        };

        // JavaVMExt.runtime_ is at offset 8 (after the JNIInvokeInterface* vtable pointer)
        let runtime_raw = *((vm_ptr as usize + 8) as *const u64);
        // Strip pointer tag (Android 12+ uses TBI: top byte is tag, bits 56-63)
        let runtime = runtime_raw & 0x00FF_FFFF_FFFF_FFFF;
        if runtime == 0 {
            output_message(&format!(
                "[java hook] ClassLinker scan: null runtime ptr (raw={:#x})", runtime_raw
            ));
            return 0;
        }

        output_message(&format!(
            "[java hook] ClassLinker scan: JavaVM={:#x}, Runtime={:#x}",
            vm_ptr as u64, runtime
        ));

        // Scan Runtime struct for java_vm_ field (matches our known JavaVM*)
        // Frida scans from offset 384 to 384+800 on 64-bit
        // Compare with tag stripped (both sides) since pointers may carry MTE/TBI tags
        let vm_addr_stripped = (vm_ptr as u64) & 0x00FF_FFFF_FFFF_FFFF;
        let scan_start = 384usize;
        let scan_end = scan_start + 800;

        let mut java_vm_offset: Option<usize> = None;
        for offset in (scan_start..scan_end).step_by(8) {
            let val = *((runtime as usize + offset) as *const u64);
            let val_stripped = val & 0x00FF_FFFF_FFFF_FFFF;
            if val_stripped == vm_addr_stripped {
                java_vm_offset = Some(offset);
                output_message(&format!(
                    "[java hook] found java_vm_ at Runtime+{:#x} (val={:#x})", offset, val
                ));
                break;
            }
        }

        let java_vm_off = match java_vm_offset {
            Some(o) => o,
            None => {
                output_message("[java hook] ClassLinker scan: java_vm_ not found in Runtime");
                return 0;
            }
        };

        // Calculate classLinker offset from java_vm_ position.
        // Layout (Android 12, API 31, >= 30):
        //   ... intern_table_ / class_linker_ / signal_catcher_ / jni_id_manager_ / java_vm_ ...
        // class_linker_ is at java_vm_ - 3*8 or java_vm_ - 4*8 (try both, like Frida)
        let api_level = get_android_api_level();
        output_message(&format!("[java hook] Android API level: {}", api_level));

        let class_linker_candidates: Vec<usize> = if api_level >= 33 {
            vec![java_vm_off - 4 * 8]
        } else if api_level >= 30 {
            vec![java_vm_off - 3 * 8, java_vm_off - 4 * 8]
        } else if api_level >= 29 {
            vec![java_vm_off - 2 * 8]
        } else {
            // Android 8-9: java_vm_ is after stack_trace_file_ (std::string = 3*8 bytes)
            vec![java_vm_off - 3 * 8 - 3 * 8]
        };

        for &cl_off in &class_linker_candidates {
            let class_linker_raw = *((runtime as usize + cl_off) as *const u64);
            let class_linker = class_linker_raw & 0x00FF_FFFF_FFFF_FFFF; // strip tag
            if class_linker == 0 {
                continue;
            }

            // intern_table_ is right before class_linker_ in Runtime
            let intern_table_off = cl_off - 8;
            let intern_table_raw = *((runtime as usize + intern_table_off) as *const u64);
            let intern_table = intern_table_raw & 0x00FF_FFFF_FFFF_FFFF; // strip tag
            if intern_table == 0 {
                continue;
            }

            output_message(&format!(
                "[java hook] candidate: classLinker={:#x} (Runtime+{:#x}), internTable={:#x} (Runtime+{:#x})",
                class_linker, cl_off, intern_table, intern_table_off
            ));

            // Now scan ClassLinker for the intern_table_ pointer to find the anchor
            // Frida scans from offset 200 to 200+800 on 64-bit
            // Compare with tag stripped
            let cl_scan_start = 200usize;
            let cl_scan_end = cl_scan_start + 800;

            let mut intern_table_cl_offset: Option<usize> = None;
            for offset in (cl_scan_start..cl_scan_end).step_by(8) {
                let val = *((class_linker as usize + offset) as *const u64);
                let val_stripped = val & 0x00FF_FFFF_FFFF_FFFF;
                if val_stripped == intern_table {
                    intern_table_cl_offset = Some(offset);
                    output_message(&format!(
                        "[java hook] found intern_table_ at ClassLinker+{:#x}", offset
                    ));
                    break;
                }
            }

            let it_off = match intern_table_cl_offset {
                Some(o) => o,
                None => {
                    output_message("[java hook] intern_table_ not found in this ClassLinker candidate");
                    continue;
                }
            };

            // Calculate quickGenericJniTrampoline offset from intern_table_
            // Layout in ClassLinker (Android 6+):
            //   intern_table_
            //   quick_resolution_trampoline_          +1
            //   quick_imt_conflict_trampoline_        +2
            //   quick_generic_jni_trampoline_         +3  (API 23-28)
            //   quick_to_interpreter_bridge_          +4
            //
            // Android 10 (API 29): delta=4
            // Android 11+ (API 30+): delta=6 (extra fields added)
            let delta: usize = if api_level >= 30 {
                6
            } else if api_level >= 29 {
                4
            } else {
                3 // API 23-28
            };

            let trampoline_off = it_off + delta * 8;
            let trampoline_addr = *((class_linker as usize + trampoline_off) as *const u64);
            // Strip PAC
            let trampoline_stripped = trampoline_addr & 0x0000_FFFF_FFFF_FFFF;

            output_message(&format!(
                "[java hook] quickGenericJniTrampoline at ClassLinker+{:#x} = {:#x} (stripped={:#x})",
                trampoline_off, trampoline_addr, trampoline_stripped
            ));

            // Validate: should be a code pointer in libart.so
            if trampoline_stripped != 0 && is_code_pointer(trampoline_stripped) {
                let mut info: libc::Dl_info = std::mem::zeroed();
                if libc::dladdr(trampoline_stripped as *const std::ffi::c_void, &mut info) != 0 {
                    let lib_name = if !info.dli_fname.is_null() {
                        std::ffi::CStr::from_ptr(info.dli_fname).to_string_lossy().to_string()
                    } else {
                        "??".to_string()
                    };
                    output_message(&format!(
                        "[java hook] trampoline is in: {}", lib_name
                    ));
                }

                output_message(&format!(
                    "[java hook] JNI trampoline from ClassLinker: {:#x}", trampoline_stripped
                ));
                return trampoline_stripped;
            }
        }

        output_message("[java hook] all trampoline discovery strategies failed");
        0
    })
}

// ============================================================================
// Field cache — pre-enumerated at hook time (safe thread), used from callbacks
// ============================================================================

pub(super) struct CachedFieldInfo {
    pub(super) jni_sig: String,
    pub(super) field_id: *mut std::ffi::c_void, // jfieldID — stable across threads
}

unsafe impl Send for CachedFieldInfo {}
unsafe impl Sync for CachedFieldInfo {}

/// Cached field info per class: className → (fieldName → CachedFieldInfo)
pub(super) static FIELD_CACHE: Mutex<Option<HashMap<String, HashMap<String, CachedFieldInfo>>>> =
    Mutex::new(None);

/// Enumerate and cache all instance fields for a class (including inherited).
/// Must be called from a safe thread (not a hook callback).
pub(super) unsafe fn cache_fields_for_class(
    env: JniEnv,
    class_name: &str,
) {
    // Initialize cache if needed
    {
        let mut guard = FIELD_CACHE.lock().unwrap_or_else(|e| e.into_inner());
        if guard.is_none() {
            *guard = Some(HashMap::new());
        }
        // Skip if already cached
        if guard.as_ref().unwrap().contains_key(class_name) {
            return;
        }
    }

    // Enumerate fields using JNI reflection (safe from init thread)
    let fields = match enumerate_class_fields(env, class_name) {
        Ok(f) => f,
        Err(_) => return,
    };

    // Resolve field IDs and store in cache
    let get_field_id: GetFieldIdFn = jni_fn!(env, GetFieldIdFn, JNI_GET_FIELD_ID);
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);

    let cls = find_class_safe(env, class_name);
    if cls.is_null() {
        return;
    }

    let mut field_map = HashMap::new();
    for (name, type_name) in &fields {
        let jni_sig = java_type_to_jni(type_name);
        let c_name = match CString::new(name.as_str()) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let c_sig = match CString::new(jni_sig.as_str()) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let fid = get_field_id(env, cls, c_name.as_ptr(), c_sig.as_ptr());
        if fid.is_null() || jni_check_exc(env) {
            continue;
        }
        field_map.insert(
            name.clone(),
            CachedFieldInfo {
                jni_sig,
                field_id: fid,
            },
        );
    }

    delete_local_ref(env, cls);

    let mut guard = FIELD_CACHE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(cache) = guard.as_mut() {
        cache.insert(class_name.to_string(), field_map);
    }
}

/// Enumerate fields of a class and all its superclasses via JNI reflection.
/// Returns Vec<(fieldName, typeName)>.
unsafe fn enumerate_class_fields(
    env: JniEnv,
    class_name: &str,
) -> Result<Vec<(String, String)>, String> {
    use std::ffi::CStr;

    let reflect = REFLECT_IDS.get().ok_or("reflection IDs not cached")?;

    let find_class: FindClassFn = jni_fn!(env, FindClassFn, JNI_FIND_CLASS);
    let get_mid: GetMethodIdFn = jni_fn!(env, GetMethodIdFn, JNI_GET_METHOD_ID);
    let call_obj: CallObjectMethodAFn = jni_fn!(env, CallObjectMethodAFn, JNI_CALL_OBJECT_METHOD_A);
    let get_str: GetStringUtfCharsFn = jni_fn!(env, GetStringUtfCharsFn, JNI_GET_STRING_UTF_CHARS);
    let rel_str: ReleaseStringUtfCharsFn = jni_fn!(env, ReleaseStringUtfCharsFn, JNI_RELEASE_STRING_UTF_CHARS);
    let get_arr_len: GetArrayLengthFn = jni_fn!(env, GetArrayLengthFn, JNI_GET_ARRAY_LENGTH);
    let get_arr_elem: GetObjectArrayElementFn =
        jni_fn!(env, GetObjectArrayElementFn, JNI_GET_OBJECT_ARRAY_ELEMENT);
    let push_frame: PushLocalFrameFn = jni_fn!(env, PushLocalFrameFn, JNI_PUSH_LOCAL_FRAME);
    let pop_frame: PopLocalFrameFn = jni_fn!(env, PopLocalFrameFn, JNI_POP_LOCAL_FRAME);

    if push_frame(env, 512) < 0 {
        return Err("PushLocalFrame failed".to_string());
    }

    let cls = find_class_safe(env, class_name);
    if cls.is_null() {
        pop_frame(env, std::ptr::null_mut());
        return Err("FindClass failed".to_string());
    }

    // Get reflection method IDs (system classes — FindClass is fine)
    let c_class_cls = CString::new("java/lang/Class").unwrap();
    let c_field_cls = CString::new("java/lang/reflect/Field").unwrap();
    let class_cls = find_class(env, c_class_cls.as_ptr());
    let field_cls = find_class(env, c_field_cls.as_ptr());

    let c_get_fields = CString::new("getFields").unwrap();
    let c_get_fields_sig = CString::new("()[Ljava/lang/reflect/Field;").unwrap();
    let c_get_declared_fields = CString::new("getDeclaredFields").unwrap();
    let c_get_name = CString::new("getName").unwrap();
    let c_str_sig = CString::new("()Ljava/lang/String;").unwrap();
    let c_get_type = CString::new("getType").unwrap();
    let c_get_type_sig = CString::new("()Ljava/lang/Class;").unwrap();

    let get_fields_mid = get_mid(env, class_cls, c_get_fields.as_ptr(), c_get_fields_sig.as_ptr());
    let get_declared_fields_mid = get_mid(env, class_cls, c_get_declared_fields.as_ptr(), c_get_fields_sig.as_ptr());
    let field_get_name_mid = get_mid(env, field_cls, c_get_name.as_ptr(), c_str_sig.as_ptr());
    let field_get_type_mid = get_mid(env, field_cls, c_get_type.as_ptr(), c_get_type_sig.as_ptr());

    jni_check_exc(env);

    let mut results = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // Helper: extract fields from a Field[] array
    let mut extract_fields = |arr: *mut std::ffi::c_void| {
        if arr.is_null() { return; }
        let len = get_arr_len(env, arr);
        for i in 0..len {
            let field = get_arr_elem(env, arr, i);
            if field.is_null() { continue; }

            // getName()
            let name_jstr = call_obj(env, field, field_get_name_mid, std::ptr::null());
            if name_jstr.is_null() { continue; }
            let name_chars = get_str(env, name_jstr, std::ptr::null_mut());
            let name = CStr::from_ptr(name_chars).to_string_lossy().to_string();
            rel_str(env, name_jstr, name_chars);

            if seen.contains(&name) { continue; }

            // getType().getName()
            let type_cls_obj = call_obj(env, field, field_get_type_mid, std::ptr::null());
            if type_cls_obj.is_null() { continue; }
            let type_name_jstr = call_obj(env, type_cls_obj, reflect.class_get_name_mid, std::ptr::null());
            if type_name_jstr.is_null() { continue; }
            let tc = get_str(env, type_name_jstr, std::ptr::null_mut());
            let type_name = CStr::from_ptr(tc).to_string_lossy().to_string();
            rel_str(env, type_name_jstr, tc);

            seen.insert(name.clone());
            results.push((name, type_name));
        }
    };

    // getDeclaredFields() — own fields (including private)
    if !get_declared_fields_mid.is_null() {
        let arr = call_obj(env, cls, get_declared_fields_mid, std::ptr::null());
        if jni_check_exc(env) { /* skip */ }
        else { extract_fields(arr); }
    }

    // getFields() — all public inherited fields
    if !get_fields_mid.is_null() {
        let arr = call_obj(env, cls, get_fields_mid, std::ptr::null());
        if jni_check_exc(env) { /* skip */ }
        else { extract_fields(arr); }
    }

    pop_frame(env, std::ptr::null_mut());
    Ok(results)
}
