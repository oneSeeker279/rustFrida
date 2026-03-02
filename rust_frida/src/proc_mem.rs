#![cfg(all(target_os = "android", target_arch = "aarch64"))]

use std::fs::{File, OpenOptions};
use std::os::unix::io::AsRawFd;

/// /proc/<pid>/mem 读写封装
/// 通过 pread/pwrite 直接读写目标进程内存，offset 即目标进程虚拟地址。
/// 需要 root 权限或 ptrace attach 状态。
pub(crate) struct ProcMem {
    file: File,
}

impl ProcMem {
    pub(crate) fn open(pid: u32) -> Result<Self, String> {
        let path = format!("/proc/{}/mem", pid);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .map_err(|e| format!("打开 {} 失败: {}", path, e))?;
        Ok(ProcMem { file })
    }

    pub(crate) fn pread(&self, buf: &mut [u8], offset: u64) -> Result<usize, String> {
        loop {
            let ret = unsafe {
                libc::pread(
                    self.file.as_raw_fd(),
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    offset as libc::off_t,
                )
            };
            if ret >= 0 {
                return Ok(ret as usize);
            }
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(format!("pread 失败 offset=0x{:x}: {}", offset, err));
        }
    }

    pub(crate) fn pwrite(&self, buf: &[u8], offset: u64) -> Result<usize, String> {
        loop {
            let ret = unsafe {
                libc::pwrite(
                    self.file.as_raw_fd(),
                    buf.as_ptr() as *const libc::c_void,
                    buf.len(),
                    offset as libc::off_t,
                )
            };
            if ret >= 0 {
                return Ok(ret as usize);
            }
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(format!("pwrite 失败 offset=0x{:x}: {}", offset, err));
        }
    }

    /// 读取所有请求的字节，失败返回错误
    pub(crate) fn pread_exact(&self, buf: &mut [u8], offset: u64) -> Result<(), String> {
        let mut total = 0;
        while total < buf.len() {
            let n = self.pread(&mut buf[total..], offset + total as u64)?;
            if n == 0 {
                return Err(format!(
                    "pread EOF at offset=0x{:x}, read {}/{}",
                    offset + total as u64,
                    total,
                    buf.len()
                ));
            }
            total += n;
        }
        Ok(())
    }

    /// 写入所有请求的字节，失败返回错误
    pub(crate) fn pwrite_all(&self, buf: &[u8], offset: u64) -> Result<(), String> {
        let mut total = 0;
        while total < buf.len() {
            let n = self.pwrite(&buf[total..], offset + total as u64)?;
            if n == 0 {
                return Err(format!(
                    "pwrite 停止 at offset=0x{:x}, wrote {}/{}",
                    offset + total as u64,
                    total,
                    buf.len()
                ));
            }
            total += n;
        }
        Ok(())
    }
}
