//! Memory write operations

use crate::ffi;
use crate::jsapi::util::is_addr_accessible;
use crate::value::JSValue;
use super::helpers::{get_addr_from_arg, write_with_perm};

/// Memory.writeU8(ptr, value)
pub(super) unsafe extern "C" fn memory_write_u8(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 2 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"writeU8() requires 2 arguments\0".as_ptr() as *const _,
        );
    }

    let addr = match get_addr_from_arg(ctx, JSValue(*argv)) {
        Some(a) => a,
        None => return ffi::JS_ThrowTypeError(ctx, b"Invalid pointer\0".as_ptr() as *const _),
    };

    if !is_addr_accessible(addr, 1) {
        return ffi::JS_ThrowRangeError(ctx, b"Invalid memory address\0".as_ptr() as *const _);
    }
    let val = JSValue(*argv.add(1)).to_i64(ctx).unwrap_or(0) as u8;
    if !write_with_perm(addr, 1, || { *(addr as *mut u8) = val; }) {
        return ffi::JS_ThrowRangeError(
            ctx,
            b"writeU8(): cannot make page writable (mprotect failed)\0".as_ptr() as *const _,
        );
    }
    JSValue::undefined().raw()
}

/// Memory.writeU16(ptr, value)
pub(super) unsafe extern "C" fn memory_write_u16(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 2 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"writeU16() requires 2 arguments\0".as_ptr() as *const _,
        );
    }

    let addr = match get_addr_from_arg(ctx, JSValue(*argv)) {
        Some(a) => a,
        None => return ffi::JS_ThrowTypeError(ctx, b"Invalid pointer\0".as_ptr() as *const _),
    };

    if !is_addr_accessible(addr, 2) {
        return ffi::JS_ThrowRangeError(ctx, b"Invalid memory address\0".as_ptr() as *const _);
    }
    let val = JSValue(*argv.add(1)).to_i64(ctx).unwrap_or(0) as u16;
    if !write_with_perm(addr, 2, || { std::ptr::write_unaligned(addr as *mut u16, val); }) {
        return ffi::JS_ThrowRangeError(
            ctx,
            b"writeU16(): cannot make page writable (mprotect failed)\0".as_ptr() as *const _,
        );
    }
    JSValue::undefined().raw()
}

/// Memory.writeU32(ptr, value)
pub(super) unsafe extern "C" fn memory_write_u32(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 2 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"writeU32() requires 2 arguments\0".as_ptr() as *const _,
        );
    }

    let addr = match get_addr_from_arg(ctx, JSValue(*argv)) {
        Some(a) => a,
        None => return ffi::JS_ThrowTypeError(ctx, b"Invalid pointer\0".as_ptr() as *const _),
    };

    if !is_addr_accessible(addr, 4) {
        return ffi::JS_ThrowRangeError(ctx, b"Invalid memory address\0".as_ptr() as *const _);
    }
    let val = JSValue(*argv.add(1)).to_i64(ctx).unwrap_or(0) as u32;
    if !write_with_perm(addr, 4, || { std::ptr::write_unaligned(addr as *mut u32, val); }) {
        return ffi::JS_ThrowRangeError(
            ctx,
            b"writeU32(): cannot make page writable (mprotect failed)\0".as_ptr() as *const _,
        );
    }
    JSValue::undefined().raw()
}

/// Memory.writeU64(ptr, value)
pub(super) unsafe extern "C" fn memory_write_u64(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 2 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"writeU64() requires 2 arguments\0".as_ptr() as *const _,
        );
    }

    let addr = match get_addr_from_arg(ctx, JSValue(*argv)) {
        Some(a) => a,
        None => return ffi::JS_ThrowTypeError(ctx, b"Invalid pointer\0".as_ptr() as *const _),
    };

    if !is_addr_accessible(addr, 8) {
        return ffi::JS_ThrowRangeError(ctx, b"Invalid memory address\0".as_ptr() as *const _);
    }
    let val = JSValue(*argv.add(1)).to_u64(ctx).unwrap_or(0);
    if !write_with_perm(addr, 8, || { std::ptr::write_unaligned(addr as *mut u64, val); }) {
        return ffi::JS_ThrowRangeError(
            ctx,
            b"writeU64(): cannot make page writable (mprotect failed)\0".as_ptr() as *const _,
        );
    }
    JSValue::undefined().raw()
}

/// Memory.writePointer(ptr, value)
pub(super) unsafe extern "C" fn memory_write_pointer(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    // Same as writeU64
    memory_write_u64(ctx, _this, argc, argv)
}
