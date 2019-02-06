#ifndef SUBSTRATE_TEST_RUNTIME_H_GENERATED_
#define SUBSTRATE_TEST_RUNTIME_H_GENERATED_
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

/* import: 'env' 'ext_ed25519_verify' */
extern u32 (*Z_envZ_ext_ed25519_verifyZ_iiiii)(u32, u32, u32, u32);
/* import: 'env' 'ext_get_storage_into' */
extern u32 (*Z_envZ_ext_get_storage_intoZ_iiiiii)(u32, u32, u32, u32, u32);
/* import: 'env' 'ext_print_utf8' */
extern void (*Z_envZ_ext_print_utf8Z_vii)(u32, u32);
/* import: 'env' 'ext_print_hex' */
extern void (*Z_envZ_ext_print_hexZ_vii)(u32, u32);
/* import: 'env' 'ext_set_storage' */
extern void (*Z_envZ_ext_set_storageZ_viiii)(u32, u32, u32, u32);
/* import: 'env' 'ext_clear_storage' */
extern void (*Z_envZ_ext_clear_storageZ_vii)(u32, u32);
/* import: 'env' 'ext_storage_root' */
extern void (*Z_envZ_ext_storage_rootZ_vi)(u32);
/* import: 'env' 'ext_storage_changes_root' */
extern u32 (*Z_envZ_ext_storage_changes_rootZ_iiiji)(u32, u32, u64, u32);
/* import: 'env' 'ext_twox_128' */
extern void (*Z_envZ_ext_twox_128Z_viii)(u32, u32, u32);
/* import: 'env' 'ext_blake2_256_enumerated_trie_root' */
extern void (*Z_envZ_ext_blake2_256_enumerated_trie_rootZ_viiii)(u32, u32, u32, u32);
/* import: 'env' 'ext_print_num' */
extern void (*Z_envZ_ext_print_numZ_vj)(u64);
/* import: 'env' 'ext_malloc' */
extern u32 (*Z_envZ_ext_mallocZ_ii)(u32);
/* import: 'env' 'ext_free' */
extern void (*Z_envZ_ext_freeZ_vi)(u32);

/* export: 'memory' */
extern wasm_rt_memory_t (*WASM_RT_ADD_PREFIX(Z_memory));
/* export: '__indirect_function_table' */
extern wasm_rt_table_t (*WASM_RT_ADD_PREFIX(Z___indirect_function_table));
/* export: '__heap_base' */
extern u32 (*WASM_RT_ADD_PREFIX(Z___heap_baseZ_i));
/* export: '__data_end' */
extern u32 (*WASM_RT_ADD_PREFIX(Z___data_endZ_i));
/* export: 'Core_version' */
extern u64 (*WASM_RT_ADD_PREFIX(Z_Core_versionZ_jii))(u32, u32);
/* export: 'Core_authorities' */
extern u64 (*WASM_RT_ADD_PREFIX(Z_Core_authoritiesZ_jii))(u32, u32);
/* export: 'Core_execute_block' */
extern u64 (*WASM_RT_ADD_PREFIX(Z_Core_execute_blockZ_jii))(u32, u32);
/* export: 'Core_initialise_block' */
extern u64 (*WASM_RT_ADD_PREFIX(Z_Core_initialise_blockZ_jii))(u32, u32);
/* export: 'Metadata_metadata' */
extern u64 (*WASM_RT_ADD_PREFIX(Z_Metadata_metadataZ_jii))(u32, u32);
/* export: 'TaggedTransactionQueue_validate_transaction' */
extern u64 (*WASM_RT_ADD_PREFIX(Z_TaggedTransactionQueue_validate_transactionZ_jii))(u32, u32);
/* export: 'BlockBuilder_apply_extrinsic' */
extern u64 (*WASM_RT_ADD_PREFIX(Z_BlockBuilder_apply_extrinsicZ_jii))(u32, u32);
/* export: 'BlockBuilder_finalise_block' */
extern u64 (*WASM_RT_ADD_PREFIX(Z_BlockBuilder_finalise_blockZ_jii))(u32, u32);
/* export: 'BlockBuilder_inherent_extrinsics' */
extern u64 (*WASM_RT_ADD_PREFIX(Z_BlockBuilder_inherent_extrinsicsZ_jii))(u32, u32);
/* export: 'BlockBuilder_check_inherents' */
extern u64 (*WASM_RT_ADD_PREFIX(Z_BlockBuilder_check_inherentsZ_jii))(u32, u32);
/* export: 'BlockBuilder_random_seed' */
extern u64 (*WASM_RT_ADD_PREFIX(Z_BlockBuilder_random_seedZ_jii))(u32, u32);
/* export: 'TestAPI_balance_of' */
extern u64 (*WASM_RT_ADD_PREFIX(Z_TestAPI_balance_ofZ_jii))(u32, u32);
/* export: 'TestAPI_benchmark_add_one' */
extern u64 (*WASM_RT_ADD_PREFIX(Z_TestAPI_benchmark_add_oneZ_jii))(u32, u32);
/* export: 'TestAPI_benchmark_vector_add_one' */
extern u64 (*WASM_RT_ADD_PREFIX(Z_TestAPI_benchmark_vector_add_oneZ_jii))(u32, u32);
/* export: 'TestAPI_fail_convert_parameter' */
extern u64 (*WASM_RT_ADD_PREFIX(Z_TestAPI_fail_convert_parameterZ_jii))(u32, u32);
/* export: 'TestAPI_fail_convert_return_value' */
extern u64 (*WASM_RT_ADD_PREFIX(Z_TestAPI_fail_convert_return_valueZ_jii))(u32, u32);
/* export: 'AuraApi_slot_duration' */
extern u64 (*WASM_RT_ADD_PREFIX(Z_AuraApi_slot_durationZ_jii))(u32, u32);
#ifdef __cplusplus
}
#endif

#endif  /* SUBSTRATE_TEST_RUNTIME_H_GENERATED_ */
