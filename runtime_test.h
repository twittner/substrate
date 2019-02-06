#ifndef RUNTIME_TEST_H_GENERATED_
#define RUNTIME_TEST_H_GENERATED_
#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#include "wasm-rt.h"

#ifndef WASM_RT_MODULE_PREFIX
#define WASM_RT_MODULE_PREFIX
#endif

#define WASM_RT_PASTE_(x, y) x ## y
#define WASM_RT_PASTE(x, y) WASM_RT_PASTE_(x, y)
#define WASM_RT_ADD_PREFIX(x) WASM_RT_PASTE(WASM_RT_MODULE_PREFIX, x)

/* TODO(binji): only use stdint.h types in header */
typedef uint8_t u8;
typedef int8_t s8;
typedef uint16_t u16;
typedef int16_t s16;
typedef uint32_t u32;
typedef int32_t s32;
typedef uint64_t u64;
typedef int64_t s64;
typedef float f32;
typedef double f64;

extern void WASM_RT_ADD_PREFIX(init)(void);

/* import: 'env' 'ext_print_utf8' */
extern void (*Z_envZ_ext_print_utf8Z_vii)(u32, u32);
/* import: 'env' 'ext_print_num' */
extern void (*Z_envZ_ext_print_numZ_vj)(u64);
/* import: 'env' 'ext_malloc' */
extern u32 (*Z_envZ_ext_mallocZ_ii)(u32);
/* import: 'env' 'ext_free' */
extern void (*Z_envZ_ext_freeZ_vi)(u32);
/* import: 'env' 'ext_set_storage' */
extern void (*Z_envZ_ext_set_storageZ_viiii)(u32, u32, u32, u32);
/* import: 'env' 'ext_get_allocated_storage' */
extern u32 (*Z_envZ_ext_get_allocated_storageZ_iiii)(u32, u32, u32);
/* import: 'env' 'ext_clear_prefix' */
extern void (*Z_envZ_ext_clear_prefixZ_vii)(u32, u32);
/* import: 'env' 'ext_blake2_256' */
extern void (*Z_envZ_ext_blake2_256Z_viii)(u32, u32, u32);
/* import: 'env' 'ext_twox_256' */
extern void (*Z_envZ_ext_twox_256Z_viii)(u32, u32, u32);
/* import: 'env' 'ext_twox_128' */
extern void (*Z_envZ_ext_twox_128Z_viii)(u32, u32, u32);
/* import: 'env' 'ext_ed25519_verify' */
extern u32 (*Z_envZ_ext_ed25519_verifyZ_iiiii)(u32, u32, u32, u32);
/* import: 'env' 'ext_blake2_256_enumerated_trie_root' */
extern void (*Z_envZ_ext_blake2_256_enumerated_trie_rootZ_viiii)(u32, u32, u32, u32);
/* import: 'env' 'ext_sandbox_memory_new' */
extern u32 (*Z_envZ_ext_sandbox_memory_newZ_iii)(u32, u32);
/* import: 'env' 'ext_sandbox_memory_teardown' */
extern void (*Z_envZ_ext_sandbox_memory_teardownZ_vi)(u32);
/* import: 'env' 'ext_sandbox_instantiate' */
extern u32 (*Z_envZ_ext_sandbox_instantiateZ_iiiiiii)(u32, u32, u32, u32, u32, u32);
/* import: 'env' 'ext_sandbox_instance_teardown' */
extern void (*Z_envZ_ext_sandbox_instance_teardownZ_vi)(u32);
/* import: 'env' 'ext_sandbox_invoke' */
extern u32 (*Z_envZ_ext_sandbox_invokeZ_iiiiiiiii)(u32, u32, u32, u32, u32, u32, u32, u32);

/* export: 'memory' */
extern wasm_rt_memory_t (*WASM_RT_ADD_PREFIX(Z_memory));
/* export: '__indirect_function_table' */
extern wasm_rt_table_t (*WASM_RT_ADD_PREFIX(Z___indirect_function_table));
/* export: '__heap_base' */
extern u32 (*WASM_RT_ADD_PREFIX(Z___heap_baseZ_i));
/* export: '__data_end' */
extern u32 (*WASM_RT_ADD_PREFIX(Z___data_endZ_i));
/* export: 'test_data_in' */
extern u64 (*WASM_RT_ADD_PREFIX(Z_test_data_inZ_jii))(u32, u32);
/* export: 'test_clear_prefix' */
extern u64 (*WASM_RT_ADD_PREFIX(Z_test_clear_prefixZ_jii))(u32, u32);
/* export: 'test_empty_return' */
extern u64 (*WASM_RT_ADD_PREFIX(Z_test_empty_returnZ_jii))(u32, u32);
//extern u64 test_empty_return(u32, u32);
/* export: 'test_panic' */
extern u64 (*WASM_RT_ADD_PREFIX(Z_test_panicZ_jii))(u32, u32);
/* export: 'test_conditional_panic' */
extern u64 (*WASM_RT_ADD_PREFIX(Z_test_conditional_panicZ_jii))(u32, u32);
/* export: 'test_blake2_256' */
extern u64 (*WASM_RT_ADD_PREFIX(Z_test_blake2_256Z_jii))(u32, u32);
/* export: 'test_twox_256' */
extern u64 (*WASM_RT_ADD_PREFIX(Z_test_twox_256Z_jii))(u32, u32);
/* export: 'test_twox_128' */
extern u64 (*WASM_RT_ADD_PREFIX(Z_test_twox_128Z_jii))(u32, u32);
/* export: 'test_ed25519_verify' */
extern u64 (*WASM_RT_ADD_PREFIX(Z_test_ed25519_verifyZ_jii))(u32, u32);
/* export: 'test_enumerated_trie_root' */
extern u64 (*WASM_RT_ADD_PREFIX(Z_test_enumerated_trie_rootZ_jii))(u32, u32);
/* export: 'test_sandbox' */
extern u64 (*WASM_RT_ADD_PREFIX(Z_test_sandboxZ_jii))(u32, u32);
/* export: 'test_sandbox_args' */
extern u64 (*WASM_RT_ADD_PREFIX(Z_test_sandbox_argsZ_jii))(u32, u32);
/* export: 'test_sandbox_return_val' */
extern u64 (*WASM_RT_ADD_PREFIX(Z_test_sandbox_return_valZ_jii))(u32, u32);
/* export: 'test_sandbox_instantiate' */
extern u64 (*WASM_RT_ADD_PREFIX(Z_test_sandbox_instantiateZ_jii))(u32, u32);
#ifdef __cplusplus
}
#endif

#endif  /* RUNTIME_TEST_H_GENERATED_ */
