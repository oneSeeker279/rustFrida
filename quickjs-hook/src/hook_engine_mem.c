/*
 * hook_engine_mem.c - Memory pool management, XOM-safe read, wxshadow, cache flush
 *
 * Contains: pool permission management, entry allocation/free, wxshadow patching,
 * hook_write_jump, hook_alloc, hook_relocate_instructions, hook_flush_cache.
 */

#include "hook_engine_internal.h"

/* --- Page permission helpers --- */

/*
 * Check if the page containing addr has read permission.
 * Parses /proc/self/maps to find the VMA and check perms[0] == 'r'.
 * Returns 1 if readable, 0 otherwise.
 */
int page_has_read_perm(uintptr_t addr) {
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
int read_target_safe(void* target, void* buf, size_t len) {
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

/* --- Pool permission management --- */

/*
 * Restore a target code page to R-X after patching.
 * Try 0x2000 (two pages) first in case the hook spans a page boundary.
 * Fall back to two separate 0x1000 calls when the range crosses a VMA
 * boundary (mprotect returns EINVAL for the 2-page span but succeeds per page).
 */
void restore_page_rx(uintptr_t page_start) {
    if (mprotect((void*)page_start, 0x2000, PROT_READ | PROT_EXEC) != 0) {
        mprotect((void*)page_start, 0x1000, PROT_READ | PROT_EXEC);
        mprotect((void*)(page_start + 0x1000), 0x1000, PROT_READ | PROT_EXEC);
    }
}

int pool_make_writable(void) {
    if (!g_engine.exec_mem) return -1;
    return mprotect(g_engine.exec_mem, g_engine.exec_mem_size,
                    PROT_READ | PROT_WRITE | PROT_EXEC);
}

int pool_make_executable(void) {
    if (!g_engine.exec_mem) return -1;
    return mprotect(g_engine.exec_mem, g_engine.exec_mem_size,
                    PROT_READ | PROT_EXEC);
}

/* --- Entry free list management --- */

HookEntry* alloc_entry(void) {
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

void free_entry(HookEntry* entry) {
    entry->next = g_engine.free_list;
    g_engine.free_list = entry;
}

/* --- Cache flush --- */

void hook_flush_cache(void* start, size_t size) {
    __builtin___clear_cache((char*)start, (char*)start + size);
}

/* --- wxshadow --- */

/*
 * Write data to target address via wxshadow prctl.
 * Tries pid=0 first, then getpid() as fallback.
 *
 * Returns 0 on success, HOOK_ERROR_WXSHADOW_FAILED on failure.
 */
int wxshadow_patch(void* addr, const void* buf, size_t len) {
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
int wxshadow_release(void* addr) {
    int ret;
    ret = prctl(PR_WXSHADOW_RELEASE, 0, (uintptr_t)addr, 0, 0);
    if (ret == 0) return 0;
    ret = prctl(PR_WXSHADOW_RELEASE, getpid(), (uintptr_t)addr, 0, 0);
    if (ret == 0) return 0;
    return HOOK_ERROR_WXSHADOW_FAILED;
}

/* --- Jump writing and allocation --- */

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

/* --- Instruction relocation --- */

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
