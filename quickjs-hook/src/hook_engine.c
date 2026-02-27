/*
 * hook_engine.c - ARM64 Inline Hook Engine Implementation
 *
 * Provides inline hooking functionality for ARM64 Android.
 * Uses the arm64_writer and arm64_relocator modules for code generation
 * and instruction relocation.
 */

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

/* Global engine state */
static HookEngine g_engine = {0};

/* --- Diagnostic log infrastructure --- */

static HookLogFn g_log_fn = NULL;

void hook_engine_set_log_fn(HookLogFn fn) {
    g_log_fn = fn;
}

static void hook_log(const char* fmt, ...) {
    if (!g_log_fn) return;
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    g_log_fn(buf);
}

/*
 * Check if the page containing addr has read permission.
 * Parses /proc/self/maps to find the VMA and check perms[0] == 'r'.
 * Returns 1 if readable, 0 otherwise.
 */
static int page_has_read_perm(uintptr_t addr) {
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return 0;

    char line[512];
    int readable = 0;
    while (fgets(line, sizeof(line), f)) {
        uintptr_t start = 0, end = 0;
        char perms[8] = "";
        if (sscanf(line, "%lx-%lx %7s", &start, &end, perms) >= 3) {
            if (addr >= start && addr < end) {
                readable = (perms[0] == 'r');
                break;
            }
        }
    }
    fclose(f);
    return readable;
}

/*
 * Safely read bytes from a target address.
 *
 * Strategy:
 *   1. Check VMA permission — if readable, direct memcpy.
 *   2. Otherwise mprotect to add read bit, memcpy, then restore.
 *
 * Returns 0 on success, -1 on failure.
 */
static int read_target_safe(void* target, void* buf, size_t len) {
    /* If page is already readable, just memcpy */
    if (page_has_read_perm((uintptr_t)target)) {
        memcpy(buf, target, len);
        return 0;
    }

    /* Page not readable (XOM / --x) — mprotect to add read, then memcpy */
    uintptr_t page_start = (uintptr_t)target & ~(uintptr_t)0xFFF;
    if (mprotect((void*)page_start, 0x2000, PROT_READ | PROT_EXEC) == 0) {
        memcpy(buf, target, len);
        /* restore to original r-x (mprotect already set it to r-x) */
        return 0;
    }

    hook_log("read_target_safe: mprotect failed errno=%d", errno);
    return -1;
}

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

/* --- Pool permission management (Fix 2: RWX → R-X) --- */

/*
 * Restore a target code page to R-X after patching.
 * Try 0x2000 (two pages) first in case the hook spans a page boundary.
 * Fall back to two separate 0x1000 calls when the range crosses a VMA
 * boundary (mprotect returns EINVAL for the 2-page span but succeeds per page).
 */
static void restore_page_rx(uintptr_t page_start) {
    if (mprotect((void*)page_start, 0x2000, PROT_READ | PROT_EXEC) != 0) {
        mprotect((void*)page_start, 0x1000, PROT_READ | PROT_EXEC);
        mprotect((void*)(page_start + 0x1000), 0x1000, PROT_READ | PROT_EXEC);
    }
}

static int pool_make_writable(void) {
    if (!g_engine.exec_mem) return -1;
    return mprotect(g_engine.exec_mem, g_engine.exec_mem_size,
                    PROT_READ | PROT_WRITE | PROT_EXEC);
}

static int pool_make_executable(void) {
    if (!g_engine.exec_mem) return -1;
    return mprotect(g_engine.exec_mem, g_engine.exec_mem_size,
                    PROT_READ | PROT_EXEC);
}

/* --- Entry free list management (Fix 4: memory reuse) --- */

static HookEntry* alloc_entry(void) {
    HookEntry* entry = NULL;

    if (g_engine.free_list) {
        /* Reuse from free list, preserving pool memory allocations */
        entry = g_engine.free_list;
        g_engine.free_list = entry->next;

        void* saved_trampoline = entry->trampoline;
        size_t saved_trampoline_alloc = entry->trampoline_alloc;
        void* saved_thunk = entry->thunk;
        size_t saved_thunk_alloc = entry->thunk_alloc;

        memset(entry, 0, sizeof(HookEntry));

        entry->trampoline = saved_trampoline;
        entry->trampoline_alloc = saved_trampoline_alloc;
        entry->thunk = saved_thunk;
        entry->thunk_alloc = saved_thunk_alloc;
    } else {
        entry = (HookEntry*)hook_alloc(sizeof(HookEntry));
        if (entry) memset(entry, 0, sizeof(HookEntry));
    }

    return entry;
}

static void free_entry(HookEntry* entry) {
    entry->next = g_engine.free_list;
    g_engine.free_list = entry;
}

/* Flush instruction cache */
void hook_flush_cache(void* start, size_t size) {
    __builtin___clear_cache((char*)start, (char*)start + size);
}

/*
 * Write data to target address via wxshadow prctl.
 * Tries pid=0 first, then getpid() as fallback.
 *
 * Returns 0 on success, HOOK_ERROR_WXSHADOW_FAILED on failure.
 */
static int wxshadow_patch(void* addr, const void* buf, size_t len) {
    int ret = prctl(PR_WXSHADOW_PATCH, 0, (uintptr_t)addr, (uintptr_t)buf, (int)len);
    if (ret == 0) return 0;

    ret = prctl(PR_WXSHADOW_PATCH, getpid(), (uintptr_t)addr, (uintptr_t)buf, (int)len);
    if (ret == 0) return 0;

    hook_log("wxshadow_patch failed: addr=%p len=%zu errno=%d", addr, len, errno);
    return HOOK_ERROR_WXSHADOW_FAILED;
}

/*
 * Release wxshadow shadow at addr.
 * Returns 0 on success, HOOK_ERROR_WXSHADOW_FAILED on failure.
 */
static int wxshadow_release(void* addr) {
    int ret;
    ret = prctl(PR_WXSHADOW_RELEASE, 0, (uintptr_t)addr, 0, 0);
    if (ret == 0) return 0;
    ret = prctl(PR_WXSHADOW_RELEASE, getpid(), (uintptr_t)addr, 0, 0);
    if (ret == 0) return 0;
    return HOOK_ERROR_WXSHADOW_FAILED;
}

/* Write an absolute jump using arm64_writer (MOVZ/MOVK + BR sequence) */
int hook_write_jump(void* dst, void* target) {
    if (!dst || !target) {
        return HOOK_ERROR_INVALID_PARAM;
    }

    Arm64Writer w;
    arm64_writer_init(&w, dst, (uint64_t)dst, MIN_HOOK_SIZE);
    arm64_writer_put_branch_address(&w, (uint64_t)target);

    /* Check if branch_address exceeded our buffer */
    if (arm64_writer_offset(&w) > MIN_HOOK_SIZE) {
        arm64_writer_clear(&w);
        return HOOK_ERROR_BUFFER_TOO_SMALL;
    }

    /* Fill remaining space with BRK to catch unexpected execution */
    while (arm64_writer_offset(&w) < MIN_HOOK_SIZE && arm64_writer_can_write(&w, 4)) {
        arm64_writer_put_brk_imm(&w, 0xFFFF);
    }

    int bytes_written = (int)arm64_writer_offset(&w);
    arm64_writer_clear(&w);
    return bytes_written;
}

/* Allocate from executable memory pool */
void* hook_alloc(size_t size) {
    if (!g_engine.initialized) return NULL;

    /* Align to 8 bytes */
    size = (size + 7) & ~7;

    if (g_engine.exec_mem_used + size > g_engine.exec_mem_size) {
        return NULL;
    }

    void* ptr = (uint8_t*)g_engine.exec_mem + g_engine.exec_mem_used;
    g_engine.exec_mem_used += size;
    return ptr;
}

/* Relocate instructions from a pre-read buffer (src_buf) to dst, using
 * src_pc as the original PC for PC-relative fixups.
 *
 * Separating src_buf from src_pc lets the caller read the original bytes
 * safely (e.g., via /proc/self/mem to bypass XOM) and then pass that buffer
 * here, while still computing correct relocations against the real address.
 *
 * Within-region branch fix: before the write loop we pre-create one writer
 * label per source instruction and record them in the relocator's region_labels
 * table.  Just before writing each instruction we place its label at the current
 * writer PC.  This allows arm64_relocator_write_one() to emit label-based
 * branches (rather than absolute branches to the now-overwritten original code)
 * for any PC-relative branch whose target lies inside [src_pc, src_pc+min_bytes). */
size_t hook_relocate_instructions(const void* src_buf, uint64_t src_pc, void* dst, size_t min_bytes) {
    Arm64Writer w;
    Arm64Relocator r;

    arm64_writer_init(&w, dst, (uint64_t)dst, 256);
    arm64_relocator_init(&r, src_buf, src_pc, &w);

    /* Pre-create one label per source instruction in the hook region. */
    int n = (int)(min_bytes / INSN_SIZE);
    if (n > ARM64_RELOC_MAX_REGION) n = ARM64_RELOC_MAX_REGION;
    r.region_end = src_pc + min_bytes;
    r.region_label_count = n;
    for (int i = 0; i < n; i++) {
        r.region_labels[i].src_pc = src_pc + (uint64_t)(i * INSN_SIZE);
        r.region_labels[i].label_id = arm64_writer_new_label_id(&w);
    }

    size_t src_offset = 0;
    int insn_idx = 0;
    while (src_offset < min_bytes) {
        /* Place this instruction's label at the current write position BEFORE
         * emitting the instruction so that backward references work immediately
         * and forward references are resolved during flush. */
        if (insn_idx < n)
            arm64_writer_put_label(&w, r.region_labels[insn_idx].label_id);

        if (arm64_relocator_read_one(&r) == 0) break;
        arm64_relocator_write_one(&r);
        src_offset += INSN_SIZE;
        insn_idx++;
    }

    /* Place labels for any instructions that were not reached (e.g. early EOI)
     * so that forward label references created before the loop exits are always
     * resolved to a valid (if imprecise) position. */
    for (int i = insn_idx; i < n; i++)
        arm64_writer_put_label(&w, r.region_labels[i].label_id);

    /* Flush pending label references (CBZ forward refs etc.) */
    arm64_writer_flush(&w);

    size_t written = arm64_writer_offset(&w);
    arm64_writer_clear(&w);
    arm64_relocator_clear(&r);

    return written;
}

/* Initialize the hook engine */
int hook_engine_init(void* exec_mem, size_t size) {
    if (g_engine.initialized) {
        return 0; /* Already initialized */
    }

    if (!exec_mem || size < 4096) {
        return -1;
    }

    g_engine.exec_mem = exec_mem;
    g_engine.exec_mem_size = size;
    g_engine.exec_mem_used = 0;
    g_engine.hooks = NULL;
    g_engine.free_list = NULL;
    g_engine.redirects = NULL;
    g_engine.exec_mem_page_size = (size_t)sysconf(_SC_PAGESIZE);
    pthread_mutex_init(&g_engine.lock, NULL);
    g_engine.initialized = 1;

    /* Tighten pool permissions: caller provides RWX, we keep R-X until needed */
    pool_make_executable();

    return 0;
}

/* Find hook entry by target address */
static HookEntry* find_hook(void* target) {
    HookEntry* entry = g_engine.hooks;
    while (entry) {
        if (entry->target == target) return entry;
        entry = entry->next;
    }
    return NULL;
}

/* Install a replacement hook */
void* hook_install(void* target, void* replacement, int stealth) {
    if (!g_engine.initialized || !target || !replacement) {
        return NULL;
    }

    pthread_mutex_lock(&g_engine.lock);

    /* Check if already hooked */
    if (find_hook(target)) {
        pthread_mutex_unlock(&g_engine.lock);
        return NULL;
    }

    /* Make pool writable for allocation and code generation */
    if (pool_make_writable() != 0) {
        pthread_mutex_unlock(&g_engine.lock);
        return NULL;
    }

    /* Allocate hook entry (reuse from free list if possible) */
    HookEntry* entry = alloc_entry();
    if (!entry) {
        pool_make_executable();
        pthread_mutex_unlock(&g_engine.lock);
        return NULL;
    }

    entry->target = target;
    entry->replacement = replacement;

    /* Allocate trampoline space (reuse if available and large enough) */
    if (!entry->trampoline || entry->trampoline_alloc < TRAMPOLINE_ALLOC_SIZE) {
        entry->trampoline = hook_alloc(TRAMPOLINE_ALLOC_SIZE);
        entry->trampoline_alloc = TRAMPOLINE_ALLOC_SIZE;
    }
    if (!entry->trampoline) {
        free_entry(entry);
        pool_make_executable();
        pthread_mutex_unlock(&g_engine.lock);
        return NULL;
    }

    /* Save original bytes — use XOM-safe read (bypasses hardware execute-only
     * pages on Android 10+ where VMA says r-xp but PTEs have read bit cleared).
     * Passing original_bytes to the relocator avoids re-reading the XOM page. */
    if (read_target_safe(target, entry->original_bytes, MIN_HOOK_SIZE) != 0) {
        /* All safe methods failed — last resort direct read (may SIGSEGV on XOM) */
        memcpy(entry->original_bytes, target, MIN_HOOK_SIZE);
    }
    entry->original_size = MIN_HOOK_SIZE;

    /* Relocate original instructions to trampoline.
     * Pass the pre-read buffer + real src_pc so the relocator never reads
     * directly from the (possibly XOM) target page. */
    size_t relocated_size = hook_relocate_instructions(
        entry->original_bytes, (uint64_t)target, entry->trampoline, MIN_HOOK_SIZE);

    /* Write jump back to original code after the hook */
    void* jump_back_target = (uint8_t*)target + MIN_HOOK_SIZE;
    int jump_result = hook_write_jump((uint8_t*)entry->trampoline + relocated_size, jump_back_target);
    if (jump_result < 0) {
        free_entry(entry);
        pool_make_executable();
        pthread_mutex_unlock(&g_engine.lock);
        return NULL;
    }

    /* Install hook on target. Pool is still writable (RWX) here.
     * entry->stealth (pool+0x50) and entry->next must be written before
     * pool_make_executable() removes write permission. */
    if (stealth) {
        /* Stealth mode: write jump to a temp buffer, then patch via wxshadow */
        uint8_t jump_buf[MIN_HOOK_SIZE];
        jump_result = hook_write_jump(jump_buf, replacement);
        if (jump_result < 0) {
            free_entry(entry);
            pool_make_executable();
            pthread_mutex_unlock(&g_engine.lock);
            return NULL;
        }
        if (wxshadow_patch(target, jump_buf, jump_result) != 0) {
            free_entry(entry);
            pool_make_executable();
            pthread_mutex_unlock(&g_engine.lock);
            return NULL;
        }
        entry->stealth = 1;
    } else {
        /* Normal mode: mprotect + direct write */
        uintptr_t page_start = (uintptr_t)target & ~0xFFF;
        if (mprotect((void*)page_start, 0x2000, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
            free_entry(entry);
            pool_make_executable();
            pthread_mutex_unlock(&g_engine.lock);
            return NULL;
        }
        jump_result = hook_write_jump(target, replacement);
        if (jump_result < 0) {
            restore_page_rx(page_start);
            free_entry(entry);
            pool_make_executable();
            pthread_mutex_unlock(&g_engine.lock);
            return NULL;
        }
        entry->stealth = 0;
        /* Restore target page from RWX to R-X now that the jump is written */
        restore_page_rx(page_start);
    }

    /* Flush cache */
    hook_flush_cache(target, MIN_HOOK_SIZE);
    hook_flush_cache(entry->trampoline, TRAMPOLINE_ALLOC_SIZE);

    /* Add to list (entry->next is in pool, must be written while pool is still writable) */
    entry->next = g_engine.hooks;
    g_engine.hooks = entry;

    /* Tighten pool to R-X now that all pool writes are done */
    pool_make_executable();

    void* trampoline = entry->trampoline;
    pthread_mutex_unlock(&g_engine.lock);
    return trampoline;
}

/* Generate thunk code for attach hook using arm64_writer */
static void* generate_attach_thunk(HookEntry* entry, HookCallback on_enter,
                                    HookCallback on_leave, void* user_data,
                                    size_t* thunk_size_out) {
    void* thunk_mem;

    /* Reuse thunk memory from free list entry if available and large enough */
    if (entry->thunk && entry->thunk_alloc >= THUNK_ALLOC_SIZE) {
        thunk_mem = entry->thunk;
    } else {
        thunk_mem = hook_alloc(THUNK_ALLOC_SIZE);
        if (!thunk_mem) return NULL;
        entry->thunk = thunk_mem;
        entry->thunk_alloc = THUNK_ALLOC_SIZE;
    }

    Arm64Writer w;
    arm64_writer_init(&w, thunk_mem, (uint64_t)thunk_mem, THUNK_ALLOC_SIZE);

    /* Allocate stack space for HookContext (256 bytes) + saved LR (8 bytes) + alignment */
    /* HookContext: x0-x30 (31*8=248) + sp (8) + pc (8) + nzcv (8) = 272 bytes */
    /* Round up to 16-byte alignment: 288 bytes */
    uint64_t stack_size = 288;
    arm64_writer_put_sub_reg_reg_imm(&w, ARM64_REG_SP, ARM64_REG_SP, stack_size);

    /* Save x0-x30 to context on stack */
    for (int i = 0; i < 30; i += 2) {
        arm64_writer_put_stp_reg_reg_reg_offset(&w, ARM64_REG_X0 + i, ARM64_REG_X0 + i + 1,
                                                 ARM64_REG_SP, i * 8, ARM64_INDEX_SIGNED_OFFSET);
    }
    /* Save x30 (LR) */
    arm64_writer_put_str_reg_reg_offset(&w, ARM64_REG_X30, ARM64_REG_SP, 240);

    /* Save SP before we modified it (add back our allocation) */
    arm64_writer_put_add_reg_reg_imm(&w, ARM64_REG_X16, ARM64_REG_SP, stack_size);
    arm64_writer_put_str_reg_reg_offset(&w, ARM64_REG_X16, ARM64_REG_SP, 248); /* sp offset */

    /* Save original PC (target address) to context */
    arm64_writer_put_ldr_reg_u64(&w, ARM64_REG_X16, (uint64_t)entry->target);
    arm64_writer_put_str_reg_reg_offset(&w, ARM64_REG_X16, ARM64_REG_SP, 256); /* pc offset */

    /* Save NZCV condition flags to context.nzcv ([SP+264]).
     * All instructions above (SUB/STP/STR/ADD/LDR) are non-flag-setting variants,
     * so NZCV is still intact at this point and reflects the hooked function's entry state.
     * X17 is safe to use as scratch here — it was already saved to [SP+136] by the STP loop. */
    arm64_writer_put_mrs_reg(&w, ARM64_REG_X17, 0xDA10); /* MRS X17, NZCV */
    arm64_writer_put_str_reg_reg_offset(&w, ARM64_REG_X17, ARM64_REG_SP, 264); /* nzcv offset */

    /* Call on_enter callback if set */
    if (on_enter) {
        /* Set up arguments: X0 = &HookContext, X1 = user_data */
        arm64_writer_put_mov_reg_reg(&w, ARM64_REG_X0, ARM64_REG_SP);
        arm64_writer_put_ldr_reg_u64(&w, ARM64_REG_X1, (uint64_t)user_data);

        /* Call on_enter */
        arm64_writer_put_ldr_reg_u64(&w, ARM64_REG_X16, (uint64_t)on_enter);
        arm64_writer_put_blr_reg(&w, ARM64_REG_X16);
    }

    /* Restore x0-x15 from the saved HookContext.
     * x0-x7:  function arguments — the on_enter callback may have modified them.
     * x8:     indirect result register (XR) — must be preserved for struct-return fns.
     * x9-x15: caller-saved scratch — restore so the original function sees the same
     *          values it would have received had there been no thunk in the way.
     * x16:    NOT restored here — we keep it as scratch to load the trampoline address.
     * x17-x18: restored after the trampoline load (see below). */
    for (int i = 0; i < 16; i += 2) {
        arm64_writer_put_ldp_reg_reg_reg_offset(&w, ARM64_REG_X0 + i, ARM64_REG_X0 + i + 1,
                                                 ARM64_REG_SP, i * 8, ARM64_INDEX_SIGNED_OFFSET);
    }

    /* Call original function via trampoline.
     * Load the trampoline address into x16 first (the only window where x16 is
     * unavailable as general scratch), then restore x17-x18 from context, then
     * execute BLR x16 so the original function runs with all registers intact. */
    arm64_writer_put_ldr_reg_u64(&w, ARM64_REG_X16, (uint64_t)entry->trampoline);
    /* Restore x17-x18 now that x16 holds the trampoline address */
    arm64_writer_put_ldp_reg_reg_reg_offset(&w, ARM64_REG_X17, ARM64_REG_X18,
                                             ARM64_REG_SP, 136, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_blr_reg(&w, ARM64_REG_X16);

    /* Save return value (x0) back to context */
    arm64_writer_put_str_reg_reg_offset(&w, ARM64_REG_X0, ARM64_REG_SP, 0);

    /* Call on_leave callback if set */
    if (on_leave) {
        /* Set up arguments: X0 = &HookContext, X1 = user_data */
        arm64_writer_put_mov_reg_reg(&w, ARM64_REG_X0, ARM64_REG_SP);
        arm64_writer_put_ldr_reg_u64(&w, ARM64_REG_X1, (uint64_t)user_data);

        /* Call on_leave */
        arm64_writer_put_ldr_reg_u64(&w, ARM64_REG_X16, (uint64_t)on_leave);
        arm64_writer_put_blr_reg(&w, ARM64_REG_X16);
    }

    /* Restore x0 (return value, possibly modified by on_leave) */
    arm64_writer_put_ldr_reg_reg_offset(&w, ARM64_REG_X0, ARM64_REG_SP, 0);

    /* Restore x30 (LR) */
    arm64_writer_put_ldr_reg_reg_offset(&w, ARM64_REG_X30, ARM64_REG_SP, 240);

    /* Restore NZCV condition flags from context.nzcv ([SP+264]).
     * X17 is a caller-saved scratch register per ABI; using it here to ferry
     * the NZCV value to MSR does not violate any calling convention. */
    arm64_writer_put_ldr_reg_reg_offset(&w, ARM64_REG_X17, ARM64_REG_SP, 264); /* nzcv offset */
    arm64_writer_put_msr_reg(&w, 0xDA10, ARM64_REG_X17); /* MSR NZCV, X17 */

    /* Deallocate stack */
    arm64_writer_put_add_reg_reg_imm(&w, ARM64_REG_SP, ARM64_REG_SP, stack_size);

    /* Return */
    arm64_writer_put_ret(&w);

    /* Flush any pending labels */
    arm64_writer_flush(&w);

    *thunk_size_out = arm64_writer_offset(&w);
    arm64_writer_clear(&w);

    return thunk_mem;
}

/* Install a Frida-style hook with callbacks */
int hook_attach(void* target, HookCallback on_enter, HookCallback on_leave, void* user_data, int stealth) {
    if (!g_engine.initialized) return HOOK_ERROR_NOT_INITIALIZED;
    if (!target) return HOOK_ERROR_INVALID_PARAM;
    if (!on_enter && !on_leave) return HOOK_ERROR_INVALID_PARAM;

    pthread_mutex_lock(&g_engine.lock);

    if (find_hook(target)) {
        pthread_mutex_unlock(&g_engine.lock);
        return HOOK_ERROR_ALREADY_HOOKED;
    }

    /* Make pool writable for allocation and code generation */
    if (pool_make_writable() != 0) {
        hook_log("hook_attach: pool_make_writable failed");
        pthread_mutex_unlock(&g_engine.lock);
        return HOOK_ERROR_MPROTECT_FAILED;
    }

    /* Allocate hook entry (reuse from free list if possible) */
    HookEntry* entry = alloc_entry();
    if (!entry) {
        pool_make_executable();
        pthread_mutex_unlock(&g_engine.lock);
        return HOOK_ERROR_ALLOC_FAILED;
    }

    entry->target = target;
    entry->on_enter = on_enter;
    entry->on_leave = on_leave;
    entry->user_data = user_data;

    /* Save original bytes — use XOM-safe read (bypasses hardware execute-only
     * pages on Android 10+ where VMA says r-xp but PTEs have read bit cleared). */
    if (read_target_safe(target, entry->original_bytes, MIN_HOOK_SIZE) != 0) {
        memcpy(entry->original_bytes, target, MIN_HOOK_SIZE);
    }
    entry->original_size = MIN_HOOK_SIZE;

    /* Allocate trampoline (reuse if available and large enough) */
    if (!entry->trampoline || entry->trampoline_alloc < TRAMPOLINE_ALLOC_SIZE) {
        entry->trampoline = hook_alloc(TRAMPOLINE_ALLOC_SIZE);
        entry->trampoline_alloc = TRAMPOLINE_ALLOC_SIZE;
    }
    if (!entry->trampoline) {
        free_entry(entry);
        pool_make_executable();
        pthread_mutex_unlock(&g_engine.lock);
        return HOOK_ERROR_ALLOC_FAILED;
    }

    /* Relocate original instructions to trampoline.
     * Pass the pre-read buffer + real src_pc so the relocator never reads
     * directly from the (possibly XOM) target page. */
    size_t relocated_size = hook_relocate_instructions(
        entry->original_bytes, (uint64_t)target, entry->trampoline, MIN_HOOK_SIZE);

    /* Write jump back to original code after the hook */
    void* jump_back_target = (uint8_t*)target + MIN_HOOK_SIZE;
    int jump_result = hook_write_jump((uint8_t*)entry->trampoline + relocated_size, jump_back_target);
    if (jump_result < 0) {
        free_entry(entry);
        pool_make_executable();
        pthread_mutex_unlock(&g_engine.lock);
        return jump_result;
    }

    /* Generate thunk code */
    size_t thunk_size = 0;
    void* thunk_mem = generate_attach_thunk(entry, on_enter, on_leave, user_data, &thunk_size);
    if (!thunk_mem) {
        free_entry(entry);
        pool_make_executable();
        pthread_mutex_unlock(&g_engine.lock);
        return HOOK_ERROR_ALLOC_FAILED;
    }

    /* Install hook on target. Pool is still writable (RWX) here.
     * entry->stealth and entry->next are in the pool and MUST be written
     * before pool_make_executable() removes write permission. */
    if (stealth) {
        /* Stealth mode: write jump to temp buffer, patch via wxshadow */
        uint8_t jump_buf[MIN_HOOK_SIZE];
        jump_result = hook_write_jump(jump_buf, thunk_mem);
        if (jump_result < 0) {
            free_entry(entry);
            pool_make_executable();
            pthread_mutex_unlock(&g_engine.lock);
            return jump_result;
        }
        if (wxshadow_patch(target, jump_buf, jump_result) != 0) {
            free_entry(entry);
            pool_make_executable();
            pthread_mutex_unlock(&g_engine.lock);
            return HOOK_ERROR_WXSHADOW_FAILED;
        }
        entry->stealth = 1;
    } else {
        /* Normal mode: mprotect + direct write (Fix 1: 0x2000 for cross-page) */
        uintptr_t page_start = (uintptr_t)target & ~0xFFF;
        if (mprotect((void*)page_start, 0x2000, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
            free_entry(entry);
            pool_make_executable();
            pthread_mutex_unlock(&g_engine.lock);
            return HOOK_ERROR_MPROTECT_FAILED;
        }
        jump_result = hook_write_jump(target, thunk_mem);
        if (jump_result < 0) {
            restore_page_rx(page_start);
            free_entry(entry);
            pool_make_executable();
            pthread_mutex_unlock(&g_engine.lock);
            return jump_result;
        }
        entry->stealth = 0;
        /* Restore target page from RWX to R-X now that the jump is written */
        restore_page_rx(page_start);
    }

    /* Flush caches.
     * Non-stealth: we wrote jump bytes directly to target (mprotect'd to RWX),
     *   so both dcache clean and icache invalidate are needed on the target page.
     * Stealth (wxshadow): the kernel patches via shadow page and handles cache
     *   coherency internally.  Do NOT flush the (XOM) target address — on some
     *   Android kernels __builtin___clear_cache triggers a fault on XOM pages
     *   even though dc/ic instructions normally don't require read permission. */
    if (!entry->stealth) {
        hook_flush_cache(target, MIN_HOOK_SIZE);
    }
    /* Stealth: wxshadow kernel handles icache coherency for the target page */
    hook_flush_cache(entry->trampoline, TRAMPOLINE_ALLOC_SIZE);
    hook_flush_cache(thunk_mem, thunk_size);

    /* Add to list (entry->next is in pool, must be written while pool is still writable) */
    entry->next = g_engine.hooks;
    g_engine.hooks = entry;

    /* Tighten pool to R-X now that all pool writes (stealth, next) are done */
    pool_make_executable();

    pthread_mutex_unlock(&g_engine.lock);
    return HOOK_OK;
}

/* Remove a hook */
int hook_remove(void* target) {
    if (!g_engine.initialized) {
        return HOOK_ERROR_NOT_INITIALIZED;
    }

    if (!target) {
        return HOOK_ERROR_INVALID_PARAM;
    }

    pthread_mutex_lock(&g_engine.lock);

    HookEntry* prev = NULL;
    HookEntry* entry = g_engine.hooks;

    while (entry) {
        if (entry->target == target) {
            if (entry->stealth) {
                /* Stealth hook: release shadow pages to restore original view */
                int rc = wxshadow_release(target);
                if (rc != 0) {
                    pthread_mutex_unlock(&g_engine.lock);
                    return HOOK_ERROR_WXSHADOW_FAILED;
                }
            } else {
                /* Normal hook: restore original bytes via mprotect + memcpy */
                uintptr_t page_start = (uintptr_t)target & ~0xFFF;
                if (mprotect((void*)page_start, 0x2000, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
                    pthread_mutex_unlock(&g_engine.lock);
                    return HOOK_ERROR_MPROTECT_FAILED;
                }
                memcpy(target, entry->original_bytes, entry->original_size);
                /* Restore target page from RWX to R-X after writing original bytes back */
                restore_page_rx(page_start);
            }
            hook_flush_cache(target, entry->original_size);

            /* Make pool writable before writing to pool-resident struct fields.
             * HookEntry nodes live in the exec pool (allocated via hook_alloc).
             * After installation the pool is R-X, so any write to prev->next or
             * entry->next without re-enabling PROT_WRITE causes SIGSEGV. */
            pool_make_writable();

            /* Remove from hook list */
            if (prev) {
                prev->next = entry->next;
            } else {
                g_engine.hooks = entry->next;
            }

            /* Move to free list for reuse instead of discarding */
            free_entry(entry);

            /* Restore pool to R-X */
            pool_make_executable();

            pthread_mutex_unlock(&g_engine.lock);
            return HOOK_OK;
        }
        prev = entry;
        entry = entry->next;
    }

    pthread_mutex_unlock(&g_engine.lock);
    return HOOK_ERROR_NOT_FOUND;
}

/* Get trampoline for hooked function */
void* hook_get_trampoline(void* target) {
    pthread_mutex_lock(&g_engine.lock);
    HookEntry* entry = find_hook(target);
    void* result = entry ? entry->trampoline : NULL;
    pthread_mutex_unlock(&g_engine.lock);
    return result;
}

/* Generate a redirect thunk (pointer-based hooking, no inline patching).
 *
 * Layout: save context → call on_enter(ctx, user_data) → restore registers →
 * BR x16 (tail-call to original_entry, preserving caller's LR).
 */
static void* generate_redirect_thunk(void* original_entry,
                                      HookCallback on_enter,
                                      void* user_data,
                                      void* thunk_mem,
                                      size_t* thunk_size_out) {
    Arm64Writer w;
    arm64_writer_init(&w, thunk_mem, (uint64_t)thunk_mem, THUNK_ALLOC_SIZE);

    /* HookContext: x0-x30 (31*8=248) + sp (8) + pc (8) + nzcv (8) = 272 bytes
     * Round up to 16-byte alignment: 288 bytes */
    uint64_t stack_size = 288;
    arm64_writer_put_sub_reg_reg_imm(&w, ARM64_REG_SP, ARM64_REG_SP, stack_size);

    /* Save x0-x30 to context on stack */
    for (int i = 0; i < 30; i += 2) {
        arm64_writer_put_stp_reg_reg_reg_offset(&w, ARM64_REG_X0 + i, ARM64_REG_X0 + i + 1,
                                                 ARM64_REG_SP, i * 8, ARM64_INDEX_SIGNED_OFFSET);
    }
    /* Save x30 (LR) */
    arm64_writer_put_str_reg_reg_offset(&w, ARM64_REG_X30, ARM64_REG_SP, 240);

    /* Save SP (before our allocation) */
    arm64_writer_put_add_reg_reg_imm(&w, ARM64_REG_X16, ARM64_REG_SP, stack_size);
    arm64_writer_put_str_reg_reg_offset(&w, ARM64_REG_X16, ARM64_REG_SP, 248);

    /* Save original PC (original_entry address) to context.pc */
    arm64_writer_put_ldr_reg_u64(&w, ARM64_REG_X16, (uint64_t)original_entry);
    arm64_writer_put_str_reg_reg_offset(&w, ARM64_REG_X16, ARM64_REG_SP, 256);

    /* Save NZCV condition flags */
    arm64_writer_put_mrs_reg(&w, ARM64_REG_X17, 0xDA10);
    arm64_writer_put_str_reg_reg_offset(&w, ARM64_REG_X17, ARM64_REG_SP, 264);

    /* Call on_enter(ctx, user_data) */
    arm64_writer_put_mov_reg_reg(&w, ARM64_REG_X0, ARM64_REG_SP);
    arm64_writer_put_ldr_reg_u64(&w, ARM64_REG_X1, (uint64_t)user_data);
    arm64_writer_put_ldr_reg_u64(&w, ARM64_REG_X16, (uint64_t)on_enter);
    arm64_writer_put_blr_reg(&w, ARM64_REG_X16);

    /* Restore x0-x15 (arguments + scratch, possibly modified by callback) */
    for (int i = 0; i < 16; i += 2) {
        arm64_writer_put_ldp_reg_reg_reg_offset(&w, ARM64_REG_X0 + i, ARM64_REG_X0 + i + 1,
                                                 ARM64_REG_SP, i * 8, ARM64_INDEX_SIGNED_OFFSET);
    }

    /* Load original_entry into x16 for tail-call */
    arm64_writer_put_ldr_reg_u64(&w, ARM64_REG_X16, (uint64_t)original_entry);

    /* Restore x17-x18 (saved earlier by STP) */
    arm64_writer_put_ldp_reg_reg_reg_offset(&w, ARM64_REG_X17, ARM64_REG_X18,
                                             ARM64_REG_SP, 136, ARM64_INDEX_SIGNED_OFFSET);

    /* Restore x30 (LR) — critical: tail-call via BR preserves caller's LR */
    arm64_writer_put_ldr_reg_reg_offset(&w, ARM64_REG_X30, ARM64_REG_SP, 240);

    /* Restore NZCV */
    arm64_writer_put_ldr_reg_reg_offset(&w, ARM64_REG_X19, ARM64_REG_SP, 264);
    arm64_writer_put_msr_reg(&w, 0xDA10, ARM64_REG_X19);
    /* Restore x19 from context (we clobbered it for NZCV restore) */
    arm64_writer_put_ldr_reg_reg_offset(&w, ARM64_REG_X19, ARM64_REG_SP, 152);

    /* Deallocate stack */
    arm64_writer_put_add_reg_reg_imm(&w, ARM64_REG_SP, ARM64_REG_SP, stack_size);

    /* Tail-call to original entry: BR x16 (NOT BLR — preserves caller's LR) */
    arm64_writer_put_br_reg(&w, ARM64_REG_X16);

    arm64_writer_flush(&w);

    *thunk_size_out = arm64_writer_offset(&w);
    arm64_writer_clear(&w);

    return thunk_mem;
}

/* Create a redirect hook — returns thunk address, caller writes it to the pointer slot */
void* hook_create_redirect(uint64_t key, void* original_entry,
                           HookCallback on_enter, void* user_data) {
    if (!g_engine.initialized || !original_entry || !on_enter)
        return NULL;

    pthread_mutex_lock(&g_engine.lock);

    /* Check for duplicate */
    HookRedirectEntry* cur = g_engine.redirects;
    while (cur) {
        if (cur->key == key) {
            pthread_mutex_unlock(&g_engine.lock);
            return NULL;
        }
        cur = cur->next;
    }

    if (pool_make_writable() != 0) {
        pthread_mutex_unlock(&g_engine.lock);
        return NULL;
    }

    /* Allocate entry in pool */
    HookRedirectEntry* entry = (HookRedirectEntry*)hook_alloc(sizeof(HookRedirectEntry));
    if (!entry) {
        pool_make_executable();
        pthread_mutex_unlock(&g_engine.lock);
        return NULL;
    }
    memset(entry, 0, sizeof(HookRedirectEntry));

    /* Allocate thunk memory */
    void* thunk_mem = hook_alloc(THUNK_ALLOC_SIZE);
    if (!thunk_mem) {
        pool_make_executable();
        pthread_mutex_unlock(&g_engine.lock);
        return NULL;
    }

    size_t thunk_size = 0;
    void* thunk = generate_redirect_thunk(original_entry, on_enter, user_data,
                                           thunk_mem, &thunk_size);
    if (!thunk) {
        pool_make_executable();
        pthread_mutex_unlock(&g_engine.lock);
        return NULL;
    }

    entry->key = key;
    entry->original_entry = original_entry;
    entry->thunk = thunk;
    entry->thunk_alloc = THUNK_ALLOC_SIZE;
    entry->next = g_engine.redirects;
    g_engine.redirects = entry;

    hook_flush_cache(thunk, thunk_size);
    pool_make_executable();

    pthread_mutex_unlock(&g_engine.lock);
    return thunk;
}

/* Remove a redirect hook — returns original entry point (caller restores the pointer) */
void* hook_remove_redirect(uint64_t key) {
    if (!g_engine.initialized) return NULL;

    pthread_mutex_lock(&g_engine.lock);

    HookRedirectEntry* prev = NULL;
    HookRedirectEntry* entry = g_engine.redirects;

    while (entry) {
        if (entry->key == key) {
            void* original = entry->original_entry;

            pool_make_writable();

            if (prev) {
                prev->next = entry->next;
            } else {
                g_engine.redirects = entry->next;
            }

            pool_make_executable();
            pthread_mutex_unlock(&g_engine.lock);
            return original;
        }
        prev = entry;
        entry = entry->next;
    }

    pthread_mutex_unlock(&g_engine.lock);
    return NULL;
}

/* Generate a native hook thunk (for replace-with-native approach).
 *
 * Similar to redirect thunk but ends with RET instead of BR to original.
 * Used when a Java method is converted to native and this thunk serves
 * as the native function implementation (stored in ArtMethod.data_).
 *
 * Layout: save context → call on_enter(ctx, user_data) → restore x0 → RET
 */
static void* generate_native_hook_thunk(HookCallback on_enter,
                                         void* user_data,
                                         void* thunk_mem,
                                         size_t* thunk_size_out) {
    Arm64Writer w;
    arm64_writer_init(&w, thunk_mem, (uint64_t)thunk_mem, THUNK_ALLOC_SIZE);

    /* HookContext: x0-x30 (31*8=248) + sp (8) + pc (8) + nzcv (8) = 272 bytes
     * Round up to 16-byte alignment: 288 bytes */
    uint64_t stack_size = 288;
    arm64_writer_put_sub_reg_reg_imm(&w, ARM64_REG_SP, ARM64_REG_SP, stack_size);

    /* Save x0-x30 to context on stack */
    for (int i = 0; i < 30; i += 2) {
        arm64_writer_put_stp_reg_reg_reg_offset(&w, ARM64_REG_X0 + i, ARM64_REG_X0 + i + 1,
                                                 ARM64_REG_SP, i * 8, ARM64_INDEX_SIGNED_OFFSET);
    }
    /* Save x30 (LR) */
    arm64_writer_put_str_reg_reg_offset(&w, ARM64_REG_X30, ARM64_REG_SP, 240);

    /* Save SP (before our allocation) */
    arm64_writer_put_add_reg_reg_imm(&w, ARM64_REG_X16, ARM64_REG_SP, stack_size);
    arm64_writer_put_str_reg_reg_offset(&w, ARM64_REG_X16, ARM64_REG_SP, 248);

    /* PC = 0 (not meaningful for native hooks) */
    arm64_writer_put_ldr_reg_u64(&w, ARM64_REG_X16, 0);
    arm64_writer_put_str_reg_reg_offset(&w, ARM64_REG_X16, ARM64_REG_SP, 256);

    /* Save NZCV condition flags */
    arm64_writer_put_mrs_reg(&w, ARM64_REG_X17, 0xDA10);
    arm64_writer_put_str_reg_reg_offset(&w, ARM64_REG_X17, ARM64_REG_SP, 264);

    /* Call on_enter(ctx, user_data) */
    arm64_writer_put_mov_reg_reg(&w, ARM64_REG_X0, ARM64_REG_SP);
    arm64_writer_put_ldr_reg_u64(&w, ARM64_REG_X1, (uint64_t)user_data);
    arm64_writer_put_ldr_reg_u64(&w, ARM64_REG_X16, (uint64_t)on_enter);
    arm64_writer_put_blr_reg(&w, ARM64_REG_X16);

    /* Restore x0 (return value, possibly modified by callback) */
    arm64_writer_put_ldr_reg_reg_offset(&w, ARM64_REG_X0, ARM64_REG_SP, 0);

    /* Restore x30 (LR — return address set by ART's JNI trampoline) */
    arm64_writer_put_ldr_reg_reg_offset(&w, ARM64_REG_X30, ARM64_REG_SP, 240);

    /* Deallocate stack */
    arm64_writer_put_add_reg_reg_imm(&w, ARM64_REG_SP, ARM64_REG_SP, stack_size);

    /* Return to ART's JNI trampoline */
    arm64_writer_put_ret(&w);

    arm64_writer_flush(&w);
    *thunk_size_out = arm64_writer_offset(&w);
    arm64_writer_clear(&w);

    return thunk_mem;
}

/* Create a native hook trampoline — called by ART's JNI trampoline as a native function.
 * Returns the thunk address to be stored in ArtMethod.data_ field.
 * Uses the redirect entry list for tracking (shares hook_remove_redirect for cleanup). */
void* hook_create_native_trampoline(uint64_t key, HookCallback on_enter, void* user_data) {
    if (!g_engine.initialized || !on_enter)
        return NULL;

    pthread_mutex_lock(&g_engine.lock);

    /* Check for duplicate */
    HookRedirectEntry* cur = g_engine.redirects;
    while (cur) {
        if (cur->key == key) {
            pthread_mutex_unlock(&g_engine.lock);
            return NULL;
        }
        cur = cur->next;
    }

    if (pool_make_writable() != 0) {
        pthread_mutex_unlock(&g_engine.lock);
        return NULL;
    }

    /* Allocate entry in pool */
    HookRedirectEntry* entry = (HookRedirectEntry*)hook_alloc(sizeof(HookRedirectEntry));
    if (!entry) {
        pool_make_executable();
        pthread_mutex_unlock(&g_engine.lock);
        return NULL;
    }
    memset(entry, 0, sizeof(HookRedirectEntry));

    /* Allocate thunk memory */
    void* thunk_mem = hook_alloc(THUNK_ALLOC_SIZE);
    if (!thunk_mem) {
        pool_make_executable();
        pthread_mutex_unlock(&g_engine.lock);
        return NULL;
    }

    size_t thunk_size = 0;
    void* thunk = generate_native_hook_thunk(on_enter, user_data, thunk_mem, &thunk_size);
    if (!thunk) {
        pool_make_executable();
        pthread_mutex_unlock(&g_engine.lock);
        return NULL;
    }

    entry->key = key;
    entry->original_entry = NULL; /* no original entry for native hook */
    entry->thunk = thunk;
    entry->thunk_alloc = THUNK_ALLOC_SIZE;
    entry->next = g_engine.redirects;
    g_engine.redirects = entry;

    hook_flush_cache(thunk, thunk_size);
    pool_make_executable();

    pthread_mutex_unlock(&g_engine.lock);
    return thunk;
}

/* Cleanup all hooks */
void hook_engine_cleanup(void) {
    if (!g_engine.initialized) return;

    pthread_mutex_lock(&g_engine.lock);

    /* Make pool writable for cleanup state reset */
    pool_make_writable();

    /* Restore all hooked target functions to their original bytes. */
    HookEntry* entry = g_engine.hooks;
    while (entry) {
        if (entry->stealth) {
            wxshadow_release(entry->target);
        } else {
            uintptr_t page_start = (uintptr_t)entry->target & ~0xFFF;
            mprotect((void*)page_start, 0x2000, PROT_READ | PROT_WRITE | PROT_EXEC);
            memcpy(entry->target, entry->original_bytes, entry->original_size);
            /* Restore target page to R-X after writing original bytes back */
            restore_page_rx(page_start);
        }
        hook_flush_cache(entry->target, entry->original_size);
        entry = entry->next;
    }

    /* HookEntry lifetime note:
     * All HookEntry structs (including trampoline and thunk memory) live inside
     * g_engine.exec_mem (the executable pool). The pool is a single mmap'd region
     * that is released via munmap by the caller after hook_engine_cleanup() returns.
     * Therefore we do NOT iterate the list to free individual entries here — the
     * munmap in the caller frees the entire pool at once.
     *
     * WARNING: Do NOT add malloc()/free() fallback paths for alloc_entry(). If pool
     * allocations ever fall back to malloc, those pointers would be invalid after a
     * munmap and would require explicit free() here. Keep all hook memory in the pool. */

    /* Reset state — the list pointers are now dangling (pool about to be unmapped) */
    g_engine.hooks = NULL;
    g_engine.free_list = NULL;
    g_engine.redirects = NULL;
    g_engine.exec_mem_used = 0;
    g_engine.initialized = 0;

    pthread_mutex_unlock(&g_engine.lock);
    pthread_mutex_destroy(&g_engine.lock);
}
