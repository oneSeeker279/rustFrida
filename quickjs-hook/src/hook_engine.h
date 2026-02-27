/*
 * hook_engine.h - ARM64 Inline Hook Engine
 *
 * Provides inline hooking functionality for ARM64 Android.
 * Uses MOVZ/MOVK + BR X16 jump sequences (up to 20 bytes).
 */

#ifndef HOOK_ENGINE_H
#define HOOK_ENGINE_H

#include <stdint.h>
#include <stddef.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Error codes */
#define HOOK_OK                     0
#define HOOK_ERROR_NOT_INITIALIZED  -1
#define HOOK_ERROR_INVALID_PARAM    -2
#define HOOK_ERROR_ALREADY_HOOKED   -3
#define HOOK_ERROR_ALLOC_FAILED     -4
#define HOOK_ERROR_MPROTECT_FAILED  -5
#define HOOK_ERROR_NOT_FOUND        -6
#define HOOK_ERROR_BUFFER_TOO_SMALL -7
#define HOOK_ERROR_WXSHADOW_FAILED  -8

/* Hook context - contains all ARM64 registers */
typedef struct {
    uint64_t x[31];     /* x0-x30 */
    uint64_t sp;        /* Stack pointer */
    uint64_t pc;        /* Program counter (original) */
    uint64_t nzcv;      /* Condition flags */
} HookContext;

/* Callback function types */
typedef void (*HookCallback)(HookContext* ctx, void* user_data);

/* Hook entry structure */
typedef struct HookEntry {
    void* target;                   /* Original function address */
    void* trampoline;               /* Trampoline to call original */
    void* replacement;              /* Replacement function (for replace mode) */
    HookCallback on_enter;          /* Enter callback (for attach mode) */
    HookCallback on_leave;          /* Leave callback (for attach mode) */
    void* user_data;                /* User data for callbacks */
    uint8_t original_bytes[24];     /* Saved original bytes (up to 20 needed) */
    size_t original_size;           /* Number of bytes saved */
    int stealth;                    /* 1 if installed via wxshadow stealth mode */
    void* thunk;                    /* Thunk code pointer (attach mode) */
    size_t trampoline_alloc;        /* Trampoline allocated size */
    size_t thunk_alloc;             /* Thunk allocated size */
    struct HookEntry* next;         /* Next entry in list */
} HookEntry;

/* Redirect entry — replaces a function pointer (e.g. ArtMethod entry_point)
 * rather than patching inline code.  No instruction relocation needed. */
typedef struct HookRedirectEntry {
    uint64_t key;                   /* Unique identifier (e.g. ArtMethod* address) */
    void* original_entry;           /* Original entry point (for restore on unhook) */
    void* thunk;                    /* Generated redirect thunk */
    size_t thunk_alloc;             /* Thunk allocated size */
    struct HookRedirectEntry* next; /* Next entry in list */
} HookRedirectEntry;

/* Global hook engine state */
typedef struct {
    void* exec_mem;                 /* Executable memory pool */
    size_t exec_mem_size;           /* Total pool size */
    size_t exec_mem_used;           /* Used bytes */
    HookEntry* hooks;               /* Linked list of hooks */
    HookEntry* free_list;           /* Freed entries for reuse */
    HookRedirectEntry* redirects;   /* Linked list of redirect hooks */
    pthread_mutex_t lock;           /* Thread safety lock */
    size_t exec_mem_page_size;      /* Page size for mprotect */
    int initialized;                /* Initialization flag */
} HookEngine;

/*
 * Initialize the hook engine
 *
 * @param exec_mem      Pointer to executable memory region (RWX)
 * @param size          Size of the memory region
 * @return              0 on success, -1 on failure
 */
int hook_engine_init(void* exec_mem, size_t size);

/*
 * Install a simple replacement hook
 *
 * @param target        Address to hook
 * @param replacement   Replacement function address
 * @param stealth       1 to use wxshadow stealth mode, 0 for normal mode
 * @return              Pointer to trampoline (to call original), NULL on failure
 */
void* hook_install(void* target, void* replacement, int stealth);

/*
 * Install a Frida-style hook with callbacks
 *
 * @param target        Address to hook
 * @param on_enter      Callback called before the function (can be NULL)
 * @param on_leave      Callback called after the function (can be NULL)
 * @param user_data     User data passed to callbacks
 * @param stealth       1 to use wxshadow stealth mode, 0 for normal mode
 * @return              0 on success, -1 on failure
 */
int hook_attach(void* target, HookCallback on_enter, HookCallback on_leave, void* user_data, int stealth);

/*
 * Remove a hook
 *
 * @param target        Address that was hooked
 * @return              0 on success, -1 on failure
 */
int hook_remove(void* target);

/*
 * Get the trampoline for a hooked function
 *
 * @param target        Original function address
 * @return              Trampoline address, NULL if not found
 */
void* hook_get_trampoline(void* target);

/*
 * Cleanup and free all hooks
 */
void hook_engine_cleanup(void);

/* Internal functions - exposed for advanced use */

/*
 * Allocate memory from the executable pool
 *
 * @param size          Number of bytes to allocate
 * @return              Pointer to allocated memory, NULL on failure
 */
void* hook_alloc(size_t size);

/*
 * Relocate ARM64 instruction(s) to dst.
 *
 * src_buf  - pointer to a pre-read copy of the original bytes (may differ from
 *            the live address; typically entry->original_bytes read via
 *            /proc/self/mem to bypass XOM pages)
 * src_pc   - original PC of the first instruction (used for PC-relative fixups)
 * dst      - destination address in the executable pool
 * min_bytes - number of bytes to relocate
 *
 * Returns number of bytes written to dst.
 */
size_t hook_relocate_instructions(const void* src_buf, uint64_t src_pc,
                                   void* dst, size_t min_bytes);

/*
 * Generate an absolute jump (MOVZ/MOVK + BR, up to 20 bytes)
 *
 * @param dst           Where to write the jump
 * @param target        Jump target address
 * @return              Number of bytes written on success, or negative error code
 */
int hook_write_jump(void* dst, void* target);

/*
 * Clear instruction cache for modified code
 *
 * @param start         Start address
 * @param size          Size of region
 */
void hook_flush_cache(void* start, size_t size);

/*
 * Log function type: receives a null-terminated message string.
 * Set via hook_engine_set_log_fn() to route diagnostic output to Rust/socket.
 */
typedef void (*HookLogFn)(const char* msg);

/*
 * Set the log callback.  Call after hook_engine_init().
 * Pass NULL to disable logging.
 */
void hook_engine_set_log_fn(HookLogFn fn);

/*
 * Create a redirect thunk for pointer-based hooking (e.g. ArtMethod entry_point).
 *
 * Generates a thunk that: saves context → calls on_enter(ctx, user_data) →
 * restores registers → tail-calls original_entry via BR x16.
 *
 * Unlike hook_attach(), this does NOT patch target code or create a trampoline.
 * The caller is responsible for writing the returned thunk address to the
 * function pointer slot (e.g. ArtMethod->entry_point_from_quick_compiled_code_).
 *
 * @param key            Unique identifier (e.g. ArtMethod* address)
 * @param original_entry Original function entry point (for tail-call after callback)
 * @param on_enter       Callback called before the original function
 * @param user_data      User data passed to callback
 * @return               Thunk address on success, NULL on failure
 */
void* hook_create_redirect(uint64_t key, void* original_entry,
                           HookCallback on_enter, void* user_data);

/*
 * Remove a redirect hook and return the original entry point.
 *
 * @param key            The key used when creating the redirect
 * @return               Original entry point, NULL if not found
 */
void* hook_remove_redirect(uint64_t key);

/*
 * Create a native hook trampoline for ART "replace with native" hooking.
 *
 * Generates a thunk that: saves context → calls on_enter(ctx, user_data) →
 * restores x0 (return value) → returns to caller (RET).
 *
 * This thunk is designed to be called by ART's JNI trampoline as a native
 * method implementation. The callback receives x0=JNIEnv*, x1=jobject/jclass,
 * x2-x7=Java args via HookContext.
 *
 * @param key            Unique identifier (e.g. ArtMethod* address)
 * @param on_enter       Callback invoked when the method is called
 * @param user_data      User data passed to callback
 * @return               Thunk address (to store in ArtMethod.data_), NULL on failure
 */
void* hook_create_native_trampoline(uint64_t key, HookCallback on_enter, void* user_data);

#ifdef __cplusplus
}
#endif

#endif /* HOOK_ENGINE_H */
