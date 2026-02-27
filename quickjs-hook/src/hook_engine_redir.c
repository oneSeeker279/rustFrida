/*
 * hook_engine_redir.c - Redirect thunks and native hook trampolines
 *
 * Contains: generate_attach_thunk, generate_redirect_thunk,
 * hook_create_redirect, hook_remove_redirect,
 * generate_native_hook_thunk, hook_create_native_trampoline.
 */

#include "hook_engine_internal.h"

/* Generate thunk code for attach hook using arm64_writer */
void* generate_attach_thunk(HookEntry* entry, HookCallback on_enter,
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
