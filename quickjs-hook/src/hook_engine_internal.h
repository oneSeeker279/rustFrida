/*
 * hook_engine_internal.h - Internal declarations shared between hook_engine*.c files
 *
 * NOT a public API header — only included by the hook_engine implementation files.
 */

#ifndef HOOK_ENGINE_INTERNAL_H
#define HOOK_ENGINE_INTERNAL_H

#include "hook_engine.h"
#include "arm64_writer.h"
#include "arm64_relocator.h"
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdio.h>
#include <errno.h>

/* wxshadow prctl operations - shadow page patching */
#ifndef PR_WXSHADOW_PATCH
#define PR_WXSHADOW_PATCH   0x57580006  /* prctl(PR_WXSHADOW_PATCH, pid, addr, buf, len) */
#endif
#ifndef PR_WXSHADOW_RELEASE
#define PR_WXSHADOW_RELEASE 0x57580008  /* prctl(PR_WXSHADOW_RELEASE, pid, addr, 0, 0) */
#endif

/* Minimum instructions to relocate for our jump sequence.
 * arm64_writer_put_branch_address uses MOVZ/MOVK + BR:
 * - Up to 4 MOV instructions (16 bytes) for 64-bit address
 * - 1 BR instruction (4 bytes)
 * Total: 20 bytes = 5 instructions
 */
#define MIN_HOOK_SIZE 20

/* ARM64 instruction size */
#define INSN_SIZE 4

/* Default allocation sizes */
#define TRAMPOLINE_ALLOC_SIZE 256
#define THUNK_ALLOC_SIZE 512

/* --- Shared state --- */
extern HookEngine g_engine;
extern HookLogFn g_log_fn;

/* --- Diagnostic log --- */
void hook_log(const char* fmt, ...);

/* --- Memory management (hook_engine_mem.c) --- */
int page_has_read_perm(uintptr_t addr);
int read_target_safe(void* target, void* buf, size_t len);
void restore_page_rx(uintptr_t page_start);
int pool_make_writable(void);
int pool_make_executable(void);
HookEntry* alloc_entry(void);
void free_entry(HookEntry* entry);
int wxshadow_patch(void* addr, const void* buf, size_t len);
int wxshadow_release(void* addr);

/* --- Core (hook_engine.c) --- */
HookEntry* find_hook(void* target);

/* --- Redirect thunks (hook_engine_redir.c) --- */
void* generate_attach_thunk(HookEntry* entry, HookCallback on_enter,
                             HookCallback on_leave, void* user_data,
                             size_t* thunk_size_out);

#endif /* HOOK_ENGINE_INTERNAL_H */
