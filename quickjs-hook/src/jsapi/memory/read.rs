//! Memory read operations

use crate::ffi;
use crate::jsapi::ptr::create_native_pointer;
use crate::jsapi::util::is_addr_accessible;
use crate::value::JSValue;
use super::helpers::get_addr_from_arg;

/// Memory.readU8(ptr)
pub(super) unsafe extern "C" fn memory_read_u8(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(ctx, b"readU8() requires 1 argument\0".as_ptr() as *const _);
    }

    let addr = match get_addr_from_arg(ctx, JSValue(*argv)) {
        Some(a) => a,
        None => return ffi::JS_ThrowTypeError(ctx, b"Invalid pointer\0".as_ptr() as *const _),
    };

    if !is_addr_accessible(addr, 1) {
        return ffi::JS_ThrowRangeError(ctx, b"Invalid memory address\0".as_ptr() as *const _);
    }
    let val = *(addr as *const u8);
    JSValue::int(val as i32).raw()
}

/// Memory.readU16(ptr)
pub(super) unsafe extern "C" fn memory_read_u16(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"readU16() requires 1 argument\0".as_ptr() as *const _,
        );
    }

    let addr = match get_addr_from_arg(ctx, JSValue(*argv)) {
        Some(a) => a,
        None => return ffi::JS_ThrowTypeError(ctx, b"Invalid pointer\0".as_ptr() as *const _),
    };

    if !is_addr_accessible(addr, 2) {
        return ffi::JS_ThrowRangeError(ctx, b"Invalid memory address\0".as_ptr() as *const _);
    }
    let val = std::ptr::read_unaligned(addr as *const u16);
    JSValue::int(val as i32).raw()
}

/// Memory.readU32(ptr)
pub(super) unsafe extern "C" fn memory_read_u32(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"readU32() requires 1 argument\0".as_ptr() as *const _,
        );
    }

    let addr = match get_addr_from_arg(ctx, JSValue(*argv)) {
        Some(a) => a,
        None => return ffi::JS_ThrowTypeError(ctx, b"Invalid pointer\0".as_ptr() as *const _),
    };

    if !is_addr_accessible(addr, 4) {
        return ffi::JS_ThrowRangeError(ctx, b"Invalid memory address\0".as_ptr() as *const _);
    }
    let val = std::ptr::read_unaligned(addr as *const u32);
    // Use BigInt for values that might overflow i32
    ffi::JS_NewBigUint64(ctx, val as u64)
}

/// Memory.readU64(ptr)
pub(super) unsafe extern "C" fn memory_read_u64(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"readU64() requires 1 argument\0".as_ptr() as *const _,
        );
    }

    let addr = match get_addr_from_arg(ctx, JSValue(*argv)) {
        Some(a) => a,
        None => return ffi::JS_ThrowTypeError(ctx, b"Invalid pointer\0".as_ptr() as *const _),
    };

    if !is_addr_accessible(addr, 8) {
        return ffi::JS_ThrowRangeError(ctx, b"Invalid memory address\0".as_ptr() as *const _);
    }
    let val = std::ptr::read_unaligned(addr as *const u64);
    ffi::JS_NewBigUint64(ctx, val)
}

/// Memory.readPointer(ptr)
pub(super) unsafe extern "C" fn memory_read_pointer(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"readPointer() requires 1 argument\0".as_ptr() as *const _,
        );
    }

    let addr = match get_addr_from_arg(ctx, JSValue(*argv)) {
        Some(a) => a,
        None => return ffi::JS_ThrowTypeError(ctx, b"Invalid pointer\0".as_ptr() as *const _),
    };

    if !is_addr_accessible(addr, 8) {
        return ffi::JS_ThrowRangeError(ctx, b"Invalid memory address\0".as_ptr() as *const _);
    }
    let val = std::ptr::read_unaligned(addr as *const u64);
    create_native_pointer(ctx, val).raw()
}

/// Memory.readCString(ptr)
pub(super) unsafe extern "C" fn memory_read_cstring(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"readCString() requires 1 argument\0".as_ptr() as *const _,
        );
    }

    let addr = match get_addr_from_arg(ctx, JSValue(*argv)) {
        Some(a) => a,
        None => return ffi::JS_ThrowTypeError(ctx, b"Invalid pointer\0".as_ptr() as *const _),
    };

    if !is_addr_accessible(addr, 1) {
        return ffi::JS_ThrowRangeError(ctx, b"Invalid memory address\0".as_ptr() as *const _);
    }
    // Bounded scan: find '\0' within MAX_CSTRING_LEN bytes to avoid SEGV on unterminated buffers.
    const MAX_CSTRING_LEN: usize = 4096;
    let mut len = 0usize;
    while len < MAX_CSTRING_LEN {
        let byte_addr = addr + len as u64;
        if !is_addr_accessible(byte_addr, 1) {
            break;
        }
        if *(byte_addr as *const u8) == 0 {
            break;
        }
        len += 1;
    }
    if len >= MAX_CSTRING_LEN {
        return ffi::JS_ThrowRangeError(
            ctx,
            b"readCString: string exceeds maximum length (4096)\0".as_ptr() as *const _,
        );
    }
    let slice = std::slice::from_raw_parts(addr as *const u8, len);
    let s = String::from_utf8_lossy(slice);
    JSValue::string(ctx, &s).raw()
}

/// Memory.readUtf8String(ptr)
pub(super) unsafe extern "C" fn memory_read_utf8_string(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    // Same as readCString for now
    memory_read_cstring(ctx, _this, argc, argv)
}

/// Memory.readByteArray(ptr, length)
pub(super) unsafe extern "C" fn memory_read_byte_array(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 2 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"readByteArray() requires 2 arguments\0".as_ptr() as *const _,
        );
    }

    let addr = match get_addr_from_arg(ctx, JSValue(*argv)) {
        Some(a) => a,
        None => return ffi::JS_ThrowTypeError(ctx, b"Invalid pointer\0".as_ptr() as *const _),
    };

    let length = JSValue(*argv.add(1)).to_i64(ctx).unwrap_or(0) as usize;

    if !is_addr_accessible(addr, length.max(1)) {
        return ffi::JS_ThrowRangeError(ctx, b"Invalid memory address\0".as_ptr() as *const _);
    }
    // Create ArrayBuffer
    let slice = std::slice::from_raw_parts(addr as *const u8, length);
    let arr = ffi::JS_NewArrayBufferCopy(ctx, slice.as_ptr(), length);
    arr
}
