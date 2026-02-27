//! Memory helper functions

use crate::ffi;
use crate::jsapi::ptr::get_native_pointer_addr;
use crate::value::JSValue;

/// Helper to get address from argument
pub(super) unsafe fn get_addr_from_arg(ctx: *mut ffi::JSContext, val: JSValue) -> Option<u64> {
    get_native_pointer_addr(ctx, val).or_else(|| val.to_u64(ctx))
}

/// Check whether the page containing `addr` is writable by parsing /proc/self/maps.
/// Returns `true` if writable (or if the map cannot be read — assume writable to avoid
/// breaking writes to legitimate RW pages).
pub(super) fn is_page_writable(addr: u64) -> bool {
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    let file = match File::open("/proc/self/maps") {
        Ok(f) => f,
        Err(_) => return true, // can't determine; assume writable
    };
    for line in BufReader::new(file).lines().flatten() {
        // Format: "start-end perms offset dev inode pathname"
        let b = line.as_bytes();
        if let Some(dash) = b.iter().position(|&x| x == b'-') {
            let Ok(start) = u64::from_str_radix(&line[..dash], 16) else { continue };
            let rest = &line[dash + 1..];
            if let Some(sp) = rest.bytes().position(|x| x == b' ') {
                let Ok(end) = u64::from_str_radix(&rest[..sp], 16) else { continue };
                if addr >= start && addr < end {
                    // perms field immediately follows the space
                    let perms = &rest[sp + 1..];
                    return perms.len() >= 2 && perms.as_bytes()[1] == b'w';
                }
            }
        }
    }
    false // not found in maps; treat as inaccessible / read-only
}

/// Perform `write_fn` at `addr`, temporarily making the containing page(s) writable
/// if they are currently mapped R-X (e.g. code pages).
///
/// Returns `true` on success, `false` if mprotect fails.
pub(super) unsafe fn write_with_perm(addr: u64, size: usize, write_fn: impl FnOnce()) -> bool {
    if is_page_writable(addr) {
        write_fn();
        return true;
    }
    // Page is not writable (likely R-X code). Temporarily open for writing.
    const PAGE_SIZE: usize = 0x1000;
    let page_start = (addr as usize) & !(PAGE_SIZE - 1);
    // Cover two pages in case the write straddles a page boundary.
    if libc::mprotect(
        page_start as *mut libc::c_void,
        PAGE_SIZE * 2,
        libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
    ) != 0
    {
        return false;
    }
    write_fn();
    // Restore to R-X (assumption: code page).
    libc::mprotect(
        page_start as *mut libc::c_void,
        PAGE_SIZE * 2,
        libc::PROT_READ | libc::PROT_EXEC,
    );
    true
}
