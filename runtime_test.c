#include <math.h>
#include <string.h>
#include <stdio.h>

#include "runtime_test.h"
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#define LIKELY(x) __builtin_expect(!!(x), 1)

#define TRAP(x) (wasm_rt_trap(WASM_RT_TRAP_##x), 0)

#define FUNC_PROLOGUE                                            \
  if (++wasm_rt_call_stack_depth > WASM_RT_MAX_CALL_STACK_DEPTH) \
    TRAP(EXHAUSTION)

#define FUNC_EPILOGUE --wasm_rt_call_stack_depth

#define UNREACHABLE TRAP(UNREACHABLE)

#define CALL_INDIRECT(table, t, ft, x, ...)          \
  (LIKELY((x) < table.size && table.data[x].func &&  \
          table.data[x].func_type == func_types[ft]) \
       ? ((t)table.data[x].func)(__VA_ARGS__)        \
       : TRAP(CALL_INDIRECT))

#define MEMCHECK(mem, a, t)  \
  if (UNLIKELY((a) + sizeof(t) > mem->size)) TRAP(OOB)

#define DEFINE_LOAD(name, t1, t2, t3)              \
  static inline t3 name(wasm_rt_memory_t* mem, u64 addr) {   \
    MEMCHECK(mem, addr, t1);                       \
    t1 result;                                     \
    memcpy(&result, &mem->data[addr], sizeof(t1)); \
    return (t3)(t2)result;                         \
  }

#define DEFINE_STORE(name, t1, t2)                           \
  static inline void name(wasm_rt_memory_t* mem, u64 addr, t2 value) { \
    MEMCHECK(mem, addr, t1);                                 \
    t1 wrapped = (t1)value;                                  \
    memcpy(&mem->data[addr], &wrapped, sizeof(t1));          \
  }

DEFINE_LOAD(i32_load, u32, u32, u32);
DEFINE_LOAD(i64_load, u64, u64, u64);
DEFINE_LOAD(f32_load, f32, f32, f32);
DEFINE_LOAD(f64_load, f64, f64, f64);
DEFINE_LOAD(i32_load8_s, s8, s32, u32);
DEFINE_LOAD(i64_load8_s, s8, s64, u64);
DEFINE_LOAD(i32_load8_u, u8, u32, u32);
DEFINE_LOAD(i64_load8_u, u8, u64, u64);
DEFINE_LOAD(i32_load16_s, s16, s32, u32);
DEFINE_LOAD(i64_load16_s, s16, s64, u64);
DEFINE_LOAD(i32_load16_u, u16, u32, u32);
DEFINE_LOAD(i64_load16_u, u16, u64, u64);
DEFINE_LOAD(i64_load32_s, s32, s64, u64);
DEFINE_LOAD(i64_load32_u, u32, u64, u64);
DEFINE_STORE(i32_store, u32, u32);
DEFINE_STORE(i64_store, u64, u64);
DEFINE_STORE(f32_store, f32, f32);
DEFINE_STORE(f64_store, f64, f64);
DEFINE_STORE(i32_store8, u8, u32);
DEFINE_STORE(i32_store16, u16, u32);
DEFINE_STORE(i64_store8, u8, u64);
DEFINE_STORE(i64_store16, u16, u64);
DEFINE_STORE(i64_store32, u32, u64);

#define I32_CLZ(x) ((x) ? __builtin_clz(x) : 32)
#define I64_CLZ(x) ((x) ? __builtin_clzll(x) : 64)
#define I32_CTZ(x) ((x) ? __builtin_ctz(x) : 32)
#define I64_CTZ(x) ((x) ? __builtin_ctzll(x) : 64)
#define I32_POPCNT(x) (__builtin_popcount(x))
#define I64_POPCNT(x) (__builtin_popcountll(x))

#define DIV_S(ut, min, x, y)                                 \
   ((UNLIKELY((y) == 0)) ?                TRAP(DIV_BY_ZERO)  \
  : (UNLIKELY((x) == min && (y) == -1)) ? TRAP(INT_OVERFLOW) \
  : (ut)((x) / (y)))

#define REM_S(ut, min, x, y)                                \
   ((UNLIKELY((y) == 0)) ?                TRAP(DIV_BY_ZERO) \
  : (UNLIKELY((x) == min && (y) == -1)) ? 0                 \
  : (ut)((x) % (y)))

#define I32_DIV_S(x, y) DIV_S(u32, INT32_MIN, (s32)x, (s32)y)
#define I64_DIV_S(x, y) DIV_S(u64, INT64_MIN, (s64)x, (s64)y)
#define I32_REM_S(x, y) REM_S(u32, INT32_MIN, (s32)x, (s32)y)
#define I64_REM_S(x, y) REM_S(u64, INT64_MIN, (s64)x, (s64)y)

#define DIVREM_U(op, x, y) \
  ((UNLIKELY((y) == 0)) ? TRAP(DIV_BY_ZERO) : ((x) op (y)))

#define DIV_U(x, y) DIVREM_U(/, x, y)
#define REM_U(x, y) DIVREM_U(%, x, y)

#define ROTL(x, y, mask) \
  (((x) << ((y) & (mask))) | ((x) >> (((mask) - (y) + 1) & (mask))))
#define ROTR(x, y, mask) \
  (((x) >> ((y) & (mask))) | ((x) << (((mask) - (y) + 1) & (mask))))

#define I32_ROTL(x, y) ROTL(x, y, 31)
#define I64_ROTL(x, y) ROTL(x, y, 63)
#define I32_ROTR(x, y) ROTR(x, y, 31)
#define I64_ROTR(x, y) ROTR(x, y, 63)

#define FMIN(x, y)                                          \
   ((UNLIKELY((x) != (x))) ? NAN                            \
  : (UNLIKELY((y) != (y))) ? NAN                            \
  : (UNLIKELY((x) == 0 && (y) == 0)) ? (signbit(x) ? x : y) \
  : (x < y) ? x : y)

#define FMAX(x, y)                                          \
   ((UNLIKELY((x) != (x))) ? NAN                            \
  : (UNLIKELY((y) != (y))) ? NAN                            \
  : (UNLIKELY((x) == 0 && (y) == 0)) ? (signbit(x) ? y : x) \
  : (x > y) ? x : y)

#define TRUNC_S(ut, st, ft, min, max, maxop, x)                             \
   ((UNLIKELY((x) != (x))) ? TRAP(INVALID_CONVERSION)                       \
  : (UNLIKELY((x) < (ft)(min) || (x) maxop (ft)(max))) ? TRAP(INT_OVERFLOW) \
  : (ut)(st)(x))

#define I32_TRUNC_S_F32(x) TRUNC_S(u32, s32, f32, INT32_MIN, INT32_MAX, >=, x)
#define I64_TRUNC_S_F32(x) TRUNC_S(u64, s64, f32, INT64_MIN, INT64_MAX, >=, x)
#define I32_TRUNC_S_F64(x) TRUNC_S(u32, s32, f64, INT32_MIN, INT32_MAX, >,  x)
#define I64_TRUNC_S_F64(x) TRUNC_S(u64, s64, f64, INT64_MIN, INT64_MAX, >=, x)

#define TRUNC_U(ut, ft, max, maxop, x)                                    \
   ((UNLIKELY((x) != (x))) ? TRAP(INVALID_CONVERSION)                     \
  : (UNLIKELY((x) <= (ft)-1 || (x) maxop (ft)(max))) ? TRAP(INT_OVERFLOW) \
  : (ut)(x))

#define I32_TRUNC_U_F32(x) TRUNC_U(u32, f32, UINT32_MAX, >=, x)
#define I64_TRUNC_U_F32(x) TRUNC_U(u64, f32, UINT64_MAX, >=, x)
#define I32_TRUNC_U_F64(x) TRUNC_U(u32, f64, UINT32_MAX, >,  x)
#define I64_TRUNC_U_F64(x) TRUNC_U(u64, f64, UINT64_MAX, >=, x)

#define DEFINE_REINTERPRET(name, t1, t2)  \
  static inline t2 name(t1 x) {           \
    t2 result;                            \
    memcpy(&result, &x, sizeof(result));  \
    return result;                        \
  }

DEFINE_REINTERPRET(f32_reinterpret_i32, u32, f32)
DEFINE_REINTERPRET(i32_reinterpret_f32, f32, u32)
DEFINE_REINTERPRET(f64_reinterpret_i64, u64, f64)
DEFINE_REINTERPRET(i64_reinterpret_f64, f64, u64)


static u32 func_types[19];

static void init_func_types(void) {
  func_types[0] = wasm_rt_register_func_type(2, 1, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32);
  func_types[1] = wasm_rt_register_func_type(3, 1, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32);
  func_types[2] = wasm_rt_register_func_type(4, 0, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32);
  func_types[3] = wasm_rt_register_func_type(2, 0, WASM_RT_I32, WASM_RT_I32);
  func_types[4] = wasm_rt_register_func_type(1, 0, WASM_RT_I64);
  func_types[5] = wasm_rt_register_func_type(1, 1, WASM_RT_I32, WASM_RT_I32);
  func_types[6] = wasm_rt_register_func_type(1, 0, WASM_RT_I32);
  func_types[7] = wasm_rt_register_func_type(3, 0, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32);
  func_types[8] = wasm_rt_register_func_type(4, 1, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32);
  func_types[9] = wasm_rt_register_func_type(6, 1, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32);
  func_types[10] = wasm_rt_register_func_type(8, 1, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32);
  func_types[11] = wasm_rt_register_func_type(0, 0);
  func_types[12] = wasm_rt_register_func_type(5, 1, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32);
  func_types[13] = wasm_rt_register_func_type(1, 1, WASM_RT_I32, WASM_RT_I64);
  func_types[14] = wasm_rt_register_func_type(2, 1, WASM_RT_I32, WASM_RT_I32, WASM_RT_I64);
  func_types[15] = wasm_rt_register_func_type(5, 0, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32);
  func_types[16] = wasm_rt_register_func_type(6, 0, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32);
  func_types[17] = wasm_rt_register_func_type(4, 1, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32, WASM_RT_I64);
  func_types[18] = wasm_rt_register_func_type(7, 0, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32);
}

static void __wasm_call_ctors(void);
static void _ZN12parity_codec5codec6Output4push17h9ea53c9a29e96026E(u32, u32);
static u32 __rust_realloc(u32, u32, u32);
static u32 __rust_alloc(u32);
static void rust_oom(u32, u32);
static void _ZN5alloc7raw_vec17capacity_overflow17h05ed4d24a03bca6bE(void);
static void _ZN63__LT_alloc__vec__Vec_LT_T_GT__u20_as_u20_core__clone__Clone_GT_5clone17hbb9cbfdba4f2bc5fE(u32, u32);
static void _ZN49__LT_alloc__raw_vec__RawVec_LT_T_C__u20_A_GT__GT_11allocate_in28__u7b__u7b_closure_u7d__u7d_17h13224a7a8fe42f97E(void);
static void _ZN72__LT_alloc__vec__Vec_LT_T_GT__u20_as_u20_parity_codec__codec__Decode_GT_6decode17hc89f3b72474bfd56E(u32, u32);
static void _ZN4core5slice22slice_index_order_fail17h3b0dea114c74cac1E(u32, u32);
static void _ZN20substrate_primitives7sandbox27_IMPL_DECODE_FOR_TypedValue99__LT_impl_u20_parity_codec__codec__Decode_u20_for_u20_substrate_primitives__sandbox__TypedValue_GT_6decode17h4f4943e22d0021b4E(u32, u32);
static void __rust_dealloc(u32);
static void rust_begin_unwind(u32);
static u32 __rg_alloc(u32);
static void __rg_dealloc(u32);
static u32 __rg_realloc(u32, u32, u32);
static u32 __rg_alloc_zeroed(u32);
static void _ZN4core9panicking5panic17hc8c3dd99127c917dE(u32);
static void _ZN4core5slice20slice_index_len_fail17h4903095f5ffa1112E(u32, u32);
static u32 _ZN4core3fmt3num52__LT_impl_u20_core__fmt__Display_u20_for_u20_u32_GT_3fmt17h3f2435e6f3e4ac83E(u32, u32);
static void _ZN4core9panicking9panic_fmt17hc562398ea080c8caE(u32, u32);
static u32 _ZN4core3fmt9Formatter12pad_integral17h9a6bb7226e47a2eeE(u32, u32, u32, u32, u32);
static void _ZN4core3ptr18real_drop_in_place17h73c609b348f6cf67E(u32);
static u64 _ZN36__LT_T_u20_as_u20_core__any__Any_GT_11get_type_id17h1457de5e51092096E(u32);
static u32 _ZN4core3fmt9Formatter3pad17h8572ace509bf2797E(u32, u32, u32);
static void _ZN4core6option13expect_failed17he3f99b0653a0c0b7E(void);
static u32 _ZN44__LT__RF_T_u20_as_u20_core__fmt__Display_GT_3fmt17h01b6108549776650E(u32, u32);
static u32 __rust_alloc_zeroed(u32);
static void _ZN12parity_codec5codec6Encode6encode17h7199eee6cd6e7a2fE(u32, u32);
static void _ZN20substrate_primitives7sandbox27_IMPL_ENCODE_FOR_TypedValue99__LT_impl_u20_parity_codec__codec__Encode_u20_for_u20_substrate_primitives__sandbox__TypedValue_GT_9encode_to17h055d1be133032210E(u32, u32);
static void _ZN12parity_codec5codec6Encode6encode17ha70755ab770d169bE(u32, u32);
//static u64 test_data_in(u32, u32);
u64 test_data_in(u32, u32);
static u64 test_clear_prefix(u32, u32);
//static u64 test_empty_return(u32, u32);
u64 test_empty_return(u32, u32);
static u64 test_panic(u32, u32);
static void _ZN12runtime_test10test_panic28__u7b__u7b_closure_u7d__u7d_17hac0217cdb3c42e04E(void);
static u64 test_conditional_panic(u32, u32);
static u64 test_blake2_256(u32, u32);
static u64 test_twox_256(u32, u32);
static u64 test_twox_128(u32, u32);
static u64 test_ed25519_verify(u32, u32);
static u64 test_enumerated_trie_root(u32, u32);
static u64 test_sandbox(u32, u32);
static void _ZN12runtime_test17execute_sandboxed17h7fa747205b7314a3E(u32, u32, u32, u32, u32);
static void _ZN12runtime_test17execute_sandboxed10env_assert17h1a8e102f17474114E(u32, u32, u32, u32);
static void _ZN63__LT_sr_sandbox__imp__EnvironmentDefinitionBuilder_LT_T_GT__GT_13add_host_func17h50b6f5e9513eb2d0E(u32, u32, u32, u32, u32, u32);
static void _ZN12runtime_test17execute_sandboxed15env_inc_counter17h43632cbfffd814eeE(u32, u32, u32, u32);
static void _ZN63__LT_sr_sandbox__imp__EnvironmentDefinitionBuilder_LT_T_GT__GT_10add_memory17h4225e8f67fd3b451E(u32, u32, u32, u32, u32, u32);
static u64 _ZN10sr_sandbox3imp14dispatch_thunk17hd12b2ae46f5bc54cE(u32, u32, u32, u32);
static void _ZN43__LT_sr_sandbox__imp__Instance_LT_T_GT__GT_6invoke17h76aac43157c22614E(u32, u32, u32, u32, u32, u32, u32);
static u64 test_sandbox_args(u32, u32);
static u64 test_sandbox_return_val(u32, u32);
static u64 test_sandbox_instantiate(u32, u32);
static u64 _ZN10sr_sandbox3imp14dispatch_thunk17h4d4a64aa4b62dc7dE(u32, u32, u32, u32);
static u32 memset_0(u32, u32, u32);
static u32 memcpy_0(u32, u32, u32);

static u32 g0;
static u32 __heap_base;
static u32 __data_end;

static void init_globals(void) {
  g0 = 1048576u;
  __heap_base = 1049844u;
  __data_end = 1049844u;
}

static wasm_rt_memory_t memory;

static wasm_rt_table_t __indirect_function_table;

static void __wasm_call_ctors(void) {
  FUNC_PROLOGUE;
  FUNC_EPILOGUE;
}

static void _ZN12parity_codec5codec6Output4push17h9ea53c9a29e96026E(u32 p0, u32 p1) {
  u32 l2 = 0, l3 = 0, l4 = 0, l5 = 0, l6 = 0, l7 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0));
  l2 = i0;
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  p1 = i0;
  i1 = 63u;
  i0 = i0 > i1;
  if (i0) {goto B27;}
  i0 = p0;
  i1 = 4u;
  i0 += i1;
  l3 = i0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p0;
  i2 = 8u;
  i1 += i2;
  l4 = i1;
  i1 = i32_load((&memory), (u64)(i1));
  l5 = i1;
  i0 = i0 != i1;
  if (i0) {goto B26;}
  i0 = l5;
  i1 = 1u;
  i0 += i1;
  l6 = i0;
  i1 = l5;
  i0 = i0 < i1;
  if (i0) {goto B2;}
  i0 = l5;
  i1 = 1u;
  i0 <<= (i1 & 31);
  l7 = i0;
  i1 = l6;
  i2 = l6;
  i3 = l7;
  i2 = i2 < i3;
  i0 = i2 ? i0 : i1;
  l7 = i0;
  i1 = 0u;
  i0 = (u32)((s32)i0 < (s32)i1);
  if (i0) {goto B2;}
  i0 = l5;
  i0 = !(i0);
  if (i0) {goto B22;}
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = l5;
  i2 = l7;
  i0 = __rust_realloc(i0, i1, i2);
  l6 = i0;
  i0 = !(i0);
  if (i0) {goto B21;}
  goto B5;
  B27:;
  i0 = p1;
  i1 = 16384u;
  i0 = i0 >= i1;
  if (i0) {goto B25;}
  i0 = p0;
  i1 = 4u;
  i0 += i1;
  l3 = i0;
  i0 = i32_load((&memory), (u64)(i0));
  l6 = i0;
  i1 = p0;
  i2 = 8u;
  i1 += i2;
  l4 = i1;
  i1 = i32_load((&memory), (u64)(i1));
  l5 = i1;
  i0 -= i1;
  i1 = 2u;
  i0 = i0 >= i1;
  if (i0) {goto B24;}
  i0 = l5;
  i1 = 2u;
  i0 += i1;
  l7 = i0;
  i1 = l5;
  i0 = i0 < i1;
  if (i0) {goto B2;}
  i0 = l6;
  i1 = 1u;
  i0 <<= (i1 & 31);
  l5 = i0;
  i1 = l7;
  i2 = l7;
  i3 = l5;
  i2 = i2 < i3;
  i0 = i2 ? i0 : i1;
  l5 = i0;
  i1 = 0u;
  i0 = (u32)((s32)i0 < (s32)i1);
  if (i0) {goto B2;}
  i0 = l6;
  i0 = !(i0);
  if (i0) {goto B18;}
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = l6;
  i2 = l5;
  i0 = __rust_realloc(i0, i1, i2);
  l6 = i0;
  i0 = !(i0);
  if (i0) {goto B17;}
  goto B7;
  B26:;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  l6 = i0;
  goto B4;
  B25:;
  i0 = p1;
  i1 = 1073741824u;
  i0 = i0 >= i1;
  if (i0) {goto B23;}
  i0 = p0;
  i1 = 4u;
  i0 += i1;
  l3 = i0;
  i0 = i32_load((&memory), (u64)(i0));
  l6 = i0;
  i1 = p0;
  i2 = 8u;
  i1 += i2;
  l4 = i1;
  i1 = i32_load((&memory), (u64)(i1));
  l5 = i1;
  i0 -= i1;
  i1 = 4u;
  i0 = i0 >= i1;
  if (i0) {goto B20;}
  i0 = l5;
  i1 = 4u;
  i0 += i1;
  l7 = i0;
  i1 = l5;
  i0 = i0 < i1;
  if (i0) {goto B2;}
  i0 = l6;
  i1 = 1u;
  i0 <<= (i1 & 31);
  l5 = i0;
  i1 = l7;
  i2 = l7;
  i3 = l5;
  i2 = i2 < i3;
  i0 = i2 ? i0 : i1;
  l5 = i0;
  i1 = 0u;
  i0 = (u32)((s32)i0 < (s32)i1);
  if (i0) {goto B2;}
  i0 = l6;
  i0 = !(i0);
  if (i0) {goto B16;}
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = l6;
  i2 = l5;
  i0 = __rust_realloc(i0, i1, i2);
  l6 = i0;
  if (i0) {goto B15;}
  goto B10;
  B24:;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  l6 = i0;
  goto B6;
  B23:;
  i0 = p0;
  i1 = 4u;
  i0 += i1;
  l3 = i0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p0;
  i2 = 8u;
  i1 += i2;
  l4 = i1;
  i1 = i32_load((&memory), (u64)(i1));
  l5 = i1;
  i0 = i0 != i1;
  if (i0) {goto B19;}
  i0 = l5;
  i1 = 1u;
  i0 += i1;
  l6 = i0;
  i1 = l5;
  i0 = i0 < i1;
  if (i0) {goto B2;}
  i0 = l5;
  i1 = 1u;
  i0 <<= (i1 & 31);
  l7 = i0;
  i1 = l6;
  i2 = l6;
  i3 = l7;
  i2 = i2 < i3;
  i0 = i2 ? i0 : i1;
  l7 = i0;
  i1 = 0u;
  i0 = (u32)((s32)i0 < (s32)i1);
  if (i0) {goto B2;}
  i0 = l5;
  i0 = !(i0);
  if (i0) {goto B13;}
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = l5;
  i2 = l7;
  i0 = __rust_realloc(i0, i1, i2);
  l6 = i0;
  if (i0) {goto B12;}
  goto B9;
  B22:;
  i0 = l7;
  i0 = __rust_alloc(i0);
  l6 = i0;
  if (i0) {goto B5;}
  B21:;
  i0 = l7;
  i1 = 1u;
  rust_oom(i0, i1);
  UNREACHABLE;
  B20:;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  l6 = i0;
  goto B14;
  B19:;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  l6 = i0;
  goto B11;
  B18:;
  i0 = l5;
  i0 = __rust_alloc(i0);
  l6 = i0;
  if (i0) {goto B7;}
  B17:;
  i0 = l5;
  i1 = 1u;
  rust_oom(i0, i1);
  UNREACHABLE;
  B16:;
  i0 = l5;
  i0 = __rust_alloc(i0);
  l6 = i0;
  i0 = !(i0);
  if (i0) {goto B10;}
  B15:;
  i0 = p0;
  i1 = l6;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = 4u;
  i0 += i1;
  i1 = l5;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = 8u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  l5 = i0;
  B14:;
  i0 = l4;
  i1 = l5;
  i2 = 4u;
  i1 += i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l6;
  i1 = l5;
  i0 += i1;
  i1 = p1;
  i2 = 2u;
  i1 <<= (i2 & 31);
  i2 = 2u;
  i1 |= i2;
  i32_store((&memory), (u64)(i0), i1);
  goto B3;
  B13:;
  i0 = l7;
  i0 = __rust_alloc(i0);
  l6 = i0;
  i0 = !(i0);
  if (i0) {goto B9;}
  B12:;
  i0 = p0;
  i1 = l6;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = 4u;
  i0 += i1;
  i1 = l7;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = 8u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  l5 = i0;
  B11:;
  i0 = l4;
  i1 = l5;
  i2 = 1u;
  i1 += i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l6;
  i1 = l5;
  i0 += i1;
  i1 = 3u;
  i32_store8((&memory), (u64)(i0), i1);
  i0 = l3;
  i0 = i32_load((&memory), (u64)(i0));
  l6 = i0;
  i1 = l4;
  i1 = i32_load((&memory), (u64)(i1));
  l5 = i1;
  i0 -= i1;
  i1 = 4u;
  i0 = i0 >= i1;
  if (i0) {goto B31;}
  i0 = l5;
  i1 = 4u;
  i0 += i1;
  l7 = i0;
  i1 = l5;
  i0 = i0 < i1;
  if (i0) {goto B2;}
  i0 = l6;
  i1 = 1u;
  i0 <<= (i1 & 31);
  l5 = i0;
  i1 = l7;
  i2 = l7;
  i3 = l5;
  i2 = i2 < i3;
  i0 = i2 ? i0 : i1;
  l5 = i0;
  i1 = 0u;
  i0 = (u32)((s32)i0 < (s32)i1);
  if (i0) {goto B2;}
  i0 = l6;
  i0 = !(i0);
  if (i0) {goto B30;}
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = l6;
  i2 = l5;
  i0 = __rust_realloc(i0, i1, i2);
  l6 = i0;
  if (i0) {goto B29;}
  goto B8;
  B31:;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  l6 = i0;
  goto B28;
  B30:;
  i0 = l5;
  i0 = __rust_alloc(i0);
  l6 = i0;
  i0 = !(i0);
  if (i0) {goto B8;}
  B29:;
  i0 = p0;
  i1 = l6;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = 4u;
  i0 += i1;
  i1 = l5;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = 8u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  l5 = i0;
  B28:;
  i0 = l4;
  i1 = l5;
  i2 = 4u;
  i1 += i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l6;
  i1 = l5;
  i0 += i1;
  i1 = p1;
  i32_store((&memory), (u64)(i0), i1);
  goto B3;
  B10:;
  i0 = l5;
  i1 = 1u;
  rust_oom(i0, i1);
  UNREACHABLE;
  B9:;
  i0 = l7;
  i1 = 1u;
  rust_oom(i0, i1);
  UNREACHABLE;
  B8:;
  i0 = l5;
  i1 = 1u;
  rust_oom(i0, i1);
  UNREACHABLE;
  B7:;
  i0 = p0;
  i1 = l6;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = 4u;
  i0 += i1;
  i1 = l5;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = 8u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  l5 = i0;
  B6:;
  i0 = l4;
  i1 = l5;
  i2 = 2u;
  i1 += i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l6;
  i1 = l5;
  i0 += i1;
  i1 = p1;
  i2 = 2u;
  i1 <<= (i2 & 31);
  i2 = 1u;
  i1 |= i2;
  i32_store16((&memory), (u64)(i0), i1);
  goto B3;
  B5:;
  i0 = p0;
  i1 = l6;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = 4u;
  i0 += i1;
  i1 = l7;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = 8u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  l5 = i0;
  B4:;
  i0 = l4;
  i1 = l5;
  i2 = 1u;
  i1 += i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l6;
  i1 = l5;
  i0 += i1;
  i1 = p1;
  i2 = 2u;
  i1 <<= (i2 & 31);
  i32_store8((&memory), (u64)(i0), i1);
  B3:;
  i0 = l3;
  i0 = i32_load((&memory), (u64)(i0));
  l3 = i0;
  i1 = l4;
  i1 = i32_load((&memory), (u64)(i1));
  l5 = i1;
  i0 -= i1;
  i1 = p1;
  i0 = i0 >= i1;
  if (i0) {goto B34;}
  i0 = l5;
  i1 = p1;
  i0 += i1;
  l6 = i0;
  i1 = l5;
  i0 = i0 < i1;
  if (i0) {goto B2;}
  i0 = l3;
  i1 = 1u;
  i0 <<= (i1 & 31);
  l5 = i0;
  i1 = l6;
  i2 = l6;
  i3 = l5;
  i2 = i2 < i3;
  i0 = i2 ? i0 : i1;
  l5 = i0;
  i1 = 0u;
  i0 = (u32)((s32)i0 < (s32)i1);
  if (i0) {goto B2;}
  i0 = l3;
  i0 = !(i0);
  if (i0) {goto B33;}
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = l3;
  i2 = l5;
  i0 = __rust_realloc(i0, i1, i2);
  l3 = i0;
  i0 = !(i0);
  if (i0) {goto B32;}
  goto B1;
  B34:;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  l3 = i0;
  goto B0;
  B33:;
  i0 = l5;
  i0 = __rust_alloc(i0);
  l3 = i0;
  if (i0) {goto B1;}
  B32:;
  i0 = l5;
  i1 = 1u;
  rust_oom(i0, i1);
  UNREACHABLE;
  B2:;
  _ZN5alloc7raw_vec17capacity_overflow17h05ed4d24a03bca6bE();
  UNREACHABLE;
  B1:;
  i0 = p0;
  i1 = l3;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = 4u;
  i0 += i1;
  i1 = l5;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = 8u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  l5 = i0;
  B0:;
  i0 = l4;
  i1 = l5;
  i2 = p1;
  i1 += i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l3;
  i1 = l5;
  i0 += i1;
  i1 = l2;
  i2 = p1;
  i0 = memcpy_0(i0, i1, i2);
  FUNC_EPILOGUE;
}

static u32 __rust_realloc(u32 p0, u32 p1, u32 p2) {
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  i0 = p0;
  i1 = p1;
  i2 = p2;
  i0 = __rg_realloc(i0, i1, i2);
  FUNC_EPILOGUE;
  return i0;
}

static u32 __rust_alloc(u32 p0) {
  fprintf(stderr, "__rust_alloc, start, p0 %d\n", p0);
  FUNC_PROLOGUE;
  u32 i0;
  i0 = p0;
  i0 = __rg_alloc(i0);
  FUNC_EPILOGUE;
  fprintf(stderr, "__rust_alloc, end, i0 %d\n", i0);
  return i0;
}

static void rust_oom(u32 p0, u32 p1) {
  FUNC_PROLOGUE;
  u32 i0, i1;
  i0 = 1048576u;
  i1 = 34u;
  (*Z_envZ_ext_print_utf8Z_vii)(i0, i1);
  UNREACHABLE;
  FUNC_EPILOGUE;
}

static void _ZN5alloc7raw_vec17capacity_overflow17h05ed4d24a03bca6bE(void) {
  FUNC_PROLOGUE;
  u32 i0;
  i0 = 1049588u;
  _ZN4core9panicking5panic17hc8c3dd99127c917dE(i0);
  UNREACHABLE;
  FUNC_EPILOGUE;
}

static void _ZN63__LT_alloc__vec__Vec_LT_T_GT__u20_as_u20_core__clone__Clone_GT_5clone17hbb9cbfdba4f2bc5fE(u32 p0, u32 p1) {
  u32 l2 = 0, l4 = 0, l5 = 0, l6 = 0, l7 = 0, l8 = 0, l9 = 0;
  u64 l3 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1;
  u64 j0, j1;
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  l2 = i0;
  j0 = (u64)(i0);
  l3 = j0;
  j1 = 30ull;
  j0 >>= (j1 & 63);
  i0 = (u32)(j0);
  if (i0) {goto B2;}
  j0 = l3;
  j1 = 2ull;
  j0 <<= (j1 & 63);
  i0 = (u32)(j0);
  l4 = i0;
  i1 = 4294967295u;
  i0 = (u32)((s32)i0 <= (s32)i1);
  if (i0) {goto B2;}
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0));
  p1 = i0;
  i0 = l4;
  i0 = !(i0);
  if (i0) {goto B4;}
  i0 = l4;
  i0 = __rust_alloc(i0);
  l5 = i0;
  i0 = !(i0);
  if (i0) {goto B1;}
  i0 = l2;
  i0 = !(i0);
  if (i0) {goto B3;}
  goto B0;
  B4:;
  i0 = 4u;
  l5 = i0;
  i0 = l2;
  if (i0) {goto B0;}
  B3:;
  i0 = p0;
  i1 = 0u;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = p0;
  i1 = l2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = p0;
  i1 = l5;
  i32_store((&memory), (u64)(i0), i1);
  goto Bfunc;
  B2:;
  _ZN49__LT_alloc__raw_vec__RawVec_LT_T_C__u20_A_GT__GT_11allocate_in28__u7b__u7b_closure_u7d__u7d_17h13224a7a8fe42f97E();
  UNREACHABLE;
  B1:;
  i0 = l4;
  i1 = 4u;
  rust_oom(i0, i1);
  UNREACHABLE;
  B0:;
  i0 = l2;
  i1 = 2u;
  i0 <<= (i1 & 31);
  l6 = i0;
  i0 = 0u;
  l7 = i0;
  i0 = l5;
  l4 = i0;
  L6: 
    i0 = p1;
    i0 = i32_load((&memory), (u64)(i0));
    l8 = i0;
    i0 = i32_load((&memory), (u64)(i0));
    i1 = 1u;
    i0 += i1;
    l9 = i0;
    i1 = 1u;
    i0 = i0 <= i1;
    if (i0) {goto B5;}
    i0 = l8;
    i1 = l9;
    i32_store((&memory), (u64)(i0), i1);
    i0 = l4;
    i1 = l8;
    i32_store((&memory), (u64)(i0), i1);
    i0 = l7;
    i1 = 1u;
    i0 += i1;
    l7 = i0;
    i0 = l4;
    i1 = 4u;
    i0 += i1;
    l4 = i0;
    i0 = p1;
    i1 = 4u;
    i0 += i1;
    p1 = i0;
    i0 = l6;
    i1 = 4294967292u;
    i0 += i1;
    l6 = i0;
    if (i0) {goto L6;}
  i0 = p0;
  i1 = l7;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = p0;
  i1 = l2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = p0;
  i1 = l5;
  i32_store((&memory), (u64)(i0), i1);
  goto Bfunc;
  B5:;
  UNREACHABLE;
  Bfunc:;
  FUNC_EPILOGUE;
}

static void _ZN49__LT_alloc__raw_vec__RawVec_LT_T_C__u20_A_GT__GT_11allocate_in28__u7b__u7b_closure_u7d__u7d_17h13224a7a8fe42f97E(void) {
  FUNC_PROLOGUE;
  _ZN5alloc7raw_vec17capacity_overflow17h05ed4d24a03bca6bE();
  UNREACHABLE;
  FUNC_EPILOGUE;
}

static void _ZN72__LT_alloc__vec__Vec_LT_T_GT__u20_as_u20_parity_codec__codec__Decode_GT_6decode17hc89f3b72474bfd56E(u32 p0, u32 p1) {
  u32 l2 = 0, l3 = 0, l4 = 0, l5 = 0, l6 = 0, l7 = 0, l8 = 0, l10 = 0, 
      l11 = 0, l12 = 0, l13 = 0;
  u64 l9 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4, i5;
  u64 j0, j1;
  i0 = g0;
  i1 = 48u;
  i0 -= i1;
  l2 = i0;
  g0 = i0;
  i0 = l2;
  i1 = 0u;
  i32_store8((&memory), (u64)(i0 + 16), i1);
  i0 = l2;
  i1 = 16u;
  i0 += i1;
  i1 = p1;
  i1 = i32_load((&memory), (u64)(i1));
  l3 = i1;
  i2 = p1;
  i2 = i32_load((&memory), (u64)(i2 + 4));
  l4 = i2;
  i3 = 0u;
  i2 = i2 != i3;
  l5 = i2;
  i0 = memcpy_0(i0, i1, i2);
  i0 = l4;
  i1 = l5;
  i0 = i0 < i1;
  if (i0) {goto B2;}
  i0 = p1;
  i1 = 4u;
  i0 += i1;
  i1 = l4;
  i2 = l5;
  i1 -= i2;
  l6 = i1;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p1;
  i1 = l3;
  i2 = l5;
  i1 += i2;
  l5 = i1;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l4;
  i0 = !(i0);
  if (i0) {goto B3;}
  i0 = l2;
  i0 = i32_load8_u((&memory), (u64)(i0 + 16));
  l3 = i0;
  i1 = 3u;
  i0 &= i1;
  l4 = i0;
  i0 = !(i0);
  if (i0) {goto B5;}
  i0 = l4;
  i1 = 1u;
  i0 = i0 == i1;
  if (i0) {goto B6;}
  i0 = l4;
  i1 = 2u;
  i0 = i0 != i1;
  if (i0) {goto B4;}
  i0 = l2;
  i1 = 0u;
  i32_store8((&memory), (u64)(i0 + 46), i1);
  i0 = l2;
  i1 = 0u;
  i32_store16((&memory), (u64)(i0 + 44), i1);
  i0 = l2;
  i1 = 44u;
  i0 += i1;
  i1 = l5;
  i2 = l6;
  i3 = 3u;
  i4 = l6;
  i5 = 3u;
  i4 = i4 < i5;
  l7 = i4;
  i2 = i4 ? i2 : i3;
  l4 = i2;
  i0 = memcpy_0(i0, i1, i2);
  i0 = p1;
  i1 = 4u;
  i0 += i1;
  i1 = l6;
  i2 = l4;
  i1 -= i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p1;
  i1 = l5;
  i2 = l4;
  i1 += i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l7;
  if (i0) {goto B3;}
  i0 = l2;
  i0 = i32_load16_u((&memory), (u64)(i0 + 44));
  i1 = l2;
  i1 = i32_load8_u((&memory), (u64)(i1 + 46));
  i2 = 16u;
  i1 <<= (i2 & 31);
  i0 |= i1;
  i1 = 8u;
  i0 <<= (i1 & 31);
  i1 = l3;
  i0 |= i1;
  i1 = 2u;
  i0 >>= (i1 & 31);
  l8 = i0;
  goto B0;
  B6:;
  i0 = l2;
  i1 = 0u;
  i32_store8((&memory), (u64)(i0 + 16), i1);
  i0 = l2;
  i1 = 16u;
  i0 += i1;
  i1 = l5;
  i2 = l6;
  i3 = 0u;
  i2 = i2 != i3;
  l4 = i2;
  i0 = memcpy_0(i0, i1, i2);
  i0 = l6;
  i1 = l4;
  i0 = i0 < i1;
  if (i0) {goto B1;}
  i0 = p1;
  i1 = 4u;
  i0 += i1;
  i1 = l6;
  i2 = l4;
  i1 -= i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p1;
  i1 = l5;
  i2 = l4;
  i1 += i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l6;
  i0 = !(i0);
  if (i0) {goto B3;}
  i0 = l2;
  i0 = i32_load8_u((&memory), (u64)(i0 + 16));
  i1 = 8u;
  i0 <<= (i1 & 31);
  i1 = l3;
  i0 |= i1;
  i1 = 2u;
  i0 >>= (i1 & 31);
  l8 = i0;
  goto B0;
  B5:;
  i0 = l3;
  i1 = 2u;
  i0 >>= (i1 & 31);
  l8 = i0;
  goto B0;
  B4:;
  i0 = l3;
  i1 = 4u;
  i0 = i0 >= i1;
  if (i0) {goto B3;}
  i0 = l2;
  i1 = 0u;
  i32_store((&memory), (u64)(i0 + 16), i1);
  i0 = l2;
  i1 = 16u;
  i0 += i1;
  i1 = l5;
  i2 = l6;
  i3 = 4u;
  i4 = l6;
  i5 = 4u;
  i4 = i4 < i5;
  l3 = i4;
  i2 = i4 ? i2 : i3;
  l4 = i2;
  i0 = memcpy_0(i0, i1, i2);
  i0 = p1;
  i1 = 4u;
  i0 += i1;
  i1 = l6;
  i2 = l4;
  i1 -= i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p1;
  i1 = l5;
  i2 = l4;
  i1 += i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l3;
  if (i0) {goto B3;}
  i0 = l2;
  i0 = i32_load((&memory), (u64)(i0 + 16));
  l8 = i0;
  goto B0;
  B3:;
  i0 = p0;
  i1 = 0u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = 48u;
  i0 += i1;
  g0 = i0;
  goto Bfunc;
  B2:;
  i0 = l5;
  i1 = l4;
  _ZN4core5slice22slice_index_order_fail17h3b0dea114c74cac1E(i0, i1);
  UNREACHABLE;
  B1:;
  i0 = l4;
  i1 = l6;
  _ZN4core5slice22slice_index_order_fail17h3b0dea114c74cac1E(i0, i1);
  UNREACHABLE;
  B0:;
  i0 = l8;
  j0 = (u64)(i0);
  l9 = j0;
  j1 = 28ull;
  j0 >>= (j1 & 63);
  i0 = (u32)(j0);
  if (i0) {goto B13;}
  j0 = l9;
  j1 = 4ull;
  j0 <<= (j1 & 63);
  i0 = (u32)(j0);
  l4 = i0;
  i1 = 4294967295u;
  i0 = (u32)((s32)i0 <= (s32)i1);
  if (i0) {goto B13;}
  i0 = l4;
  i0 = !(i0);
  if (i0) {goto B15;}
  i0 = l4;
  i0 = __rust_alloc(i0);
  l10 = i0;
  i0 = !(i0);
  if (i0) {goto B12;}
  i0 = l8;
  i0 = !(i0);
  if (i0) {goto B14;}
  goto B11;
  B15:;
  i0 = 8u;
  l10 = i0;
  i0 = l8;
  if (i0) {goto B11;}
  B14:;
  i0 = 0u;
  l4 = i0;
  i0 = 0u;
  l11 = i0;
  goto B10;
  B13:;
  _ZN49__LT_alloc__raw_vec__RawVec_LT_T_C__u20_A_GT__GT_11allocate_in28__u7b__u7b_closure_u7d__u7d_17h13224a7a8fe42f97E();
  UNREACHABLE;
  B12:;
  i0 = l4;
  i1 = 8u;
  rust_oom(i0, i1);
  UNREACHABLE;
  B11:;
  i0 = l2;
  i1 = 16u;
  i0 += i1;
  i1 = 4u;
  i0 |= i1;
  l7 = i0;
  i0 = 0u;
  l5 = i0;
  i0 = 0u;
  l6 = i0;
  i0 = 0u;
  l4 = i0;
  i0 = l8;
  l11 = i0;
  L16: 
    i0 = l2;
    i1 = 16u;
    i0 += i1;
    i1 = p1;
    _ZN20substrate_primitives7sandbox27_IMPL_DECODE_FOR_TypedValue99__LT_impl_u20_parity_codec__codec__Decode_u20_for_u20_substrate_primitives__sandbox__TypedValue_GT_6decode17h4f4943e22d0021b4E(i0, i1);
    i0 = l2;
    i1 = 32u;
    i0 += i1;
    i1 = 8u;
    i0 += i1;
    l3 = i0;
    i1 = l7;
    i2 = 8u;
    i1 += i2;
    i1 = i32_load((&memory), (u64)(i1));
    i32_store((&memory), (u64)(i0), i1);
    i0 = l2;
    i1 = l7;
    j1 = i64_load((&memory), (u64)(i1));
    i64_store((&memory), (u64)(i0 + 32), j1);
    i0 = l2;
    i0 = i32_load((&memory), (u64)(i0 + 16));
    l12 = i0;
    i1 = 4u;
    i0 = i0 == i1;
    if (i0) {goto B9;}
    i0 = l2;
    i1 = 8u;
    i0 += i1;
    l13 = i0;
    i1 = l3;
    i1 = i32_load((&memory), (u64)(i1));
    i32_store((&memory), (u64)(i0), i1);
    i0 = l2;
    i1 = l2;
    j1 = i64_load((&memory), (u64)(i1 + 32));
    i64_store((&memory), (u64)(i0), j1);
    i0 = l4;
    i1 = l11;
    i0 = i0 != i1;
    if (i0) {goto B17;}
    i0 = l6;
    i1 = l4;
    i2 = 1u;
    i1 += i2;
    l3 = i1;
    i2 = l3;
    i3 = l6;
    i2 = i2 < i3;
    i0 = i2 ? i0 : i1;
    l11 = i0;
    j0 = (u64)(i0);
    j1 = 4ull;
    j0 <<= (j1 & 63);
    l9 = j0;
    j1 = 32ull;
    j0 >>= (j1 & 63);
    i0 = (u32)(j0);
    if (i0) {goto B8;}
    j0 = l9;
    i0 = (u32)(j0);
    l3 = i0;
    i1 = 0u;
    i0 = (u32)((s32)i0 < (s32)i1);
    if (i0) {goto B8;}
    i0 = l4;
    i0 = !(i0);
    if (i0) {goto B18;}
    i0 = l10;
    i1 = l5;
    i2 = l3;
    i0 = __rust_realloc(i0, i1, i2);
    l10 = i0;
    if (i0) {goto B17;}
    goto B7;
    B18:;
    i0 = l3;
    i0 = __rust_alloc(i0);
    l10 = i0;
    i0 = !(i0);
    if (i0) {goto B7;}
    B17:;
    i0 = l10;
    i1 = l5;
    i0 += i1;
    l3 = i0;
    i1 = l12;
    i32_store((&memory), (u64)(i0), i1);
    i0 = l3;
    i1 = 12u;
    i0 += i1;
    i1 = l13;
    i1 = i32_load((&memory), (u64)(i1));
    i32_store((&memory), (u64)(i0), i1);
    i0 = l3;
    i1 = 4u;
    i0 += i1;
    i1 = l2;
    j1 = i64_load((&memory), (u64)(i1));
    i64_store((&memory), (u64)(i0), j1);
    i0 = l5;
    i1 = 16u;
    i0 += i1;
    l5 = i0;
    i0 = l6;
    i1 = 2u;
    i0 += i1;
    l6 = i0;
    i0 = l4;
    i1 = 1u;
    i0 += i1;
    l4 = i0;
    i1 = l8;
    i0 = i0 < i1;
    if (i0) {goto L16;}
  B10:;
  i0 = p0;
  i1 = l11;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = p0;
  i1 = l10;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = 8u;
  i0 += i1;
  i1 = l4;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = 48u;
  i0 += i1;
  g0 = i0;
  goto Bfunc;
  B9:;
  i0 = p0;
  i1 = 0u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l11;
  i0 = !(i0);
  if (i0) {goto B19;}
  i0 = l10;
  __rust_dealloc(i0);
  B19:;
  i0 = l2;
  i1 = 48u;
  i0 += i1;
  g0 = i0;
  goto Bfunc;
  B8:;
  _ZN5alloc7raw_vec17capacity_overflow17h05ed4d24a03bca6bE();
  UNREACHABLE;
  B7:;
  i0 = l3;
  i1 = 8u;
  rust_oom(i0, i1);
  UNREACHABLE;
  Bfunc:;
  FUNC_EPILOGUE;
}

static void _ZN4core5slice22slice_index_order_fail17h3b0dea114c74cac1E(u32 p0, u32 p1) {
  u32 l2 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  u64 j1;
  i0 = g0;
  i1 = 48u;
  i0 -= i1;
  l2 = i0;
  g0 = i0;
  i0 = l2;
  i1 = p1;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l2;
  i1 = p0;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = 44u;
  i0 += i1;
  i1 = 1u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = 28u;
  i0 += i1;
  i1 = 2u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = 1u;
  i32_store((&memory), (u64)(i0 + 36), i1);
  i0 = l2;
  j1 = 2ull;
  i64_store((&memory), (u64)(i0 + 12), j1);
  i0 = l2;
  i1 = 1049660u;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = l2;
  i1 = l2;
  i2 = 4u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 40), i1);
  i0 = l2;
  i1 = l2;
  i32_store((&memory), (u64)(i0 + 32), i1);
  i0 = l2;
  i1 = l2;
  i2 = 32u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 24), i1);
  i0 = l2;
  i1 = 8u;
  i0 += i1;
  i1 = 1049676u;
  _ZN4core9panicking9panic_fmt17hc562398ea080c8caE(i0, i1);
  UNREACHABLE;
  FUNC_EPILOGUE;
}

static void _ZN20substrate_primitives7sandbox27_IMPL_DECODE_FOR_TypedValue99__LT_impl_u20_parity_codec__codec__Decode_u20_for_u20_substrate_primitives__sandbox__TypedValue_GT_6decode17h4f4943e22d0021b4E(u32 p0, u32 p1) {
  u32 l2 = 0, l3 = 0, l4 = 0, l5 = 0, l6 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4, i5;
  u64 j1;
  i0 = g0;
  i1 = 16u;
  i0 -= i1;
  l2 = i0;
  g0 = i0;
  i0 = l2;
  i1 = 0u;
  i32_store8((&memory), (u64)(i0 + 8), i1);
  i0 = l2;
  i1 = 8u;
  i0 += i1;
  i1 = p1;
  i1 = i32_load((&memory), (u64)(i1));
  l3 = i1;
  i2 = p1;
  i2 = i32_load((&memory), (u64)(i2 + 4));
  l4 = i2;
  i3 = 0u;
  i2 = i2 != i3;
  l5 = i2;
  i0 = memcpy_0(i0, i1, i2);
  i0 = l4;
  i1 = l5;
  i0 = i0 < i1;
  if (i0) {goto B0;}
  i0 = p1;
  i1 = 4u;
  i0 += i1;
  i1 = l4;
  i2 = l5;
  i1 -= i2;
  l6 = i1;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p1;
  i1 = l3;
  i2 = l5;
  i1 += i2;
  l5 = i1;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l4;
  i0 = !(i0);
  if (i0) {goto B9;}
  i0 = l2;
  i0 = i32_load8_u((&memory), (u64)(i0 + 8));
  i1 = 4294967295u;
  i0 += i1;
  l4 = i0;
  i1 = 3u;
  i0 = i0 > i1;
  if (i0) {goto B5;}
  i0 = l4;
  switch (i0) {
    case 0: goto B10;
    case 1: goto B7;
    case 2: goto B8;
    case 3: goto B6;
    default: goto B10;
  }
  B10:;
  i0 = l2;
  i1 = 0u;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = l2;
  i1 = 8u;
  i0 += i1;
  i1 = l5;
  i2 = l6;
  i3 = 4u;
  i4 = l6;
  i5 = 4u;
  i4 = i4 < i5;
  i2 = i4 ? i2 : i3;
  l4 = i2;
  i0 = memcpy_0(i0, i1, i2);
  i0 = p1;
  i1 = 4u;
  i0 += i1;
  i1 = l6;
  i2 = l4;
  i1 -= i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p1;
  i1 = l5;
  i2 = l4;
  i1 += i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l6;
  i1 = 3u;
  i0 = i0 <= i1;
  if (i0) {goto B4;}
  i0 = p0;
  i1 = l2;
  i1 = i32_load((&memory), (u64)(i1 + 8));
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = p0;
  i1 = 0u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = 16u;
  i0 += i1;
  g0 = i0;
  goto Bfunc;
  B9:;
  i0 = p0;
  i1 = 4u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = 16u;
  i0 += i1;
  g0 = i0;
  goto Bfunc;
  B8:;
  i0 = l2;
  i1 = 0u;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = l2;
  i1 = 8u;
  i0 += i1;
  i1 = l5;
  i2 = l6;
  i3 = 4u;
  i4 = l6;
  i5 = 4u;
  i4 = i4 < i5;
  i2 = i4 ? i2 : i3;
  l4 = i2;
  i0 = memcpy_0(i0, i1, i2);
  i0 = p1;
  i1 = 4u;
  i0 += i1;
  i1 = l6;
  i2 = l4;
  i1 -= i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p1;
  i1 = l5;
  i2 = l4;
  i1 += i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l6;
  i1 = 3u;
  i0 = i0 <= i1;
  if (i0) {goto B3;}
  i0 = p0;
  i1 = l2;
  i1 = i32_load((&memory), (u64)(i1 + 8));
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = p0;
  i1 = 2u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = 16u;
  i0 += i1;
  g0 = i0;
  goto Bfunc;
  B7:;
  i0 = l2;
  j1 = 0ull;
  i64_store((&memory), (u64)(i0 + 8), j1);
  i0 = l2;
  i1 = 8u;
  i0 += i1;
  i1 = l5;
  i2 = l6;
  i3 = 8u;
  i4 = l6;
  i5 = 8u;
  i4 = i4 < i5;
  i2 = i4 ? i2 : i3;
  l4 = i2;
  i0 = memcpy_0(i0, i1, i2);
  i0 = p1;
  i1 = 4u;
  i0 += i1;
  i1 = l6;
  i2 = l4;
  i1 -= i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p1;
  i1 = l5;
  i2 = l4;
  i1 += i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l6;
  i1 = 7u;
  i0 = i0 <= i1;
  if (i0) {goto B2;}
  i0 = p0;
  i1 = 8u;
  i0 += i1;
  i1 = l2;
  j1 = i64_load((&memory), (u64)(i1 + 8));
  i64_store((&memory), (u64)(i0), j1);
  i0 = p0;
  i1 = 1u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = 16u;
  i0 += i1;
  g0 = i0;
  goto Bfunc;
  B6:;
  i0 = l2;
  j1 = 0ull;
  i64_store((&memory), (u64)(i0 + 8), j1);
  i0 = l2;
  i1 = 8u;
  i0 += i1;
  i1 = l5;
  i2 = l6;
  i3 = 8u;
  i4 = l6;
  i5 = 8u;
  i4 = i4 < i5;
  i2 = i4 ? i2 : i3;
  l4 = i2;
  i0 = memcpy_0(i0, i1, i2);
  i0 = p1;
  i1 = 4u;
  i0 += i1;
  i1 = l6;
  i2 = l4;
  i1 -= i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p1;
  i1 = l5;
  i2 = l4;
  i1 += i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l6;
  i1 = 7u;
  i0 = i0 <= i1;
  if (i0) {goto B1;}
  i0 = p0;
  i1 = 8u;
  i0 += i1;
  i1 = l2;
  j1 = i64_load((&memory), (u64)(i1 + 8));
  i64_store((&memory), (u64)(i0), j1);
  i0 = p0;
  i1 = 3u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = 16u;
  i0 += i1;
  g0 = i0;
  goto Bfunc;
  B5:;
  i0 = p0;
  i1 = 4u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = 16u;
  i0 += i1;
  g0 = i0;
  goto Bfunc;
  B4:;
  i0 = p0;
  i1 = 4u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = 16u;
  i0 += i1;
  g0 = i0;
  goto Bfunc;
  B3:;
  i0 = p0;
  i1 = 4u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = 16u;
  i0 += i1;
  g0 = i0;
  goto Bfunc;
  B2:;
  i0 = p0;
  i1 = 4u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = 16u;
  i0 += i1;
  g0 = i0;
  goto Bfunc;
  B1:;
  i0 = p0;
  i1 = 4u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = 16u;
  i0 += i1;
  g0 = i0;
  goto Bfunc;
  B0:;
  i0 = l5;
  i1 = l4;
  _ZN4core5slice22slice_index_order_fail17h3b0dea114c74cac1E(i0, i1);
  UNREACHABLE;
  Bfunc:;
  FUNC_EPILOGUE;
}

static void __rust_dealloc(u32 p0) {
  FUNC_PROLOGUE;
  u32 i0;
  i0 = p0;
  __rg_dealloc(i0);
  FUNC_EPILOGUE;
}

static void rust_begin_unwind(u32 p0) {
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  u64 j0;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 12));
  i1 = p0;
  i2 = 16u;
  i1 += i2;
  i1 = i32_load((&memory), (u64)(i1));
  (*Z_envZ_ext_print_utf8Z_vii)(i0, i1);
  i0 = p0;
  i1 = 20u;
  i0 += i1;
  j0 = i64_load32_u((&memory), (u64)(i0));
  (*Z_envZ_ext_print_numZ_vj)(j0);
  i0 = p0;
  i1 = 24u;
  i0 += i1;
  j0 = i64_load32_u((&memory), (u64)(i0));
  (*Z_envZ_ext_print_numZ_vj)(j0);
  UNREACHABLE;
  FUNC_EPILOGUE;
}

static u32 __rg_alloc(u32 p0) {
  FUNC_PROLOGUE;
  u32 i0;
  i0 = p0;
  //i0 = (*Z_envZ_ext_mallocZ_ii)(i0);
  fprintf(stderr, "before calling Z_envZ_ext_mallocZ_ii with p0 %d\n", p0);
  i0 = Z_envZ_ext_mallocZ_ii(i0);
  FUNC_EPILOGUE;
  return i0;
}

static void __rg_dealloc(u32 p0) {
  FUNC_PROLOGUE;
  u32 i0;
  i0 = p0;
  //(*Z_envZ_ext_freeZ_vi)(i0);
  Z_envZ_ext_freeZ_vi(i0);
  FUNC_EPILOGUE;
}

static u32 __rg_realloc(u32 p0, u32 p1, u32 p2) {
  u32 l3 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4, i5;
  i0 = p2;
  i0 = (*Z_envZ_ext_mallocZ_ii)(i0);
  l3 = i0;
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = l3;
  i1 = p0;
  i2 = p2;
  i3 = p1;
  i4 = p1;
  i5 = p2;
  i4 = i4 > i5;
  i2 = i4 ? i2 : i3;
  i0 = memcpy_0(i0, i1, i2);
  i0 = p0;
  (*Z_envZ_ext_freeZ_vi)(i0);
  B0:;
  i0 = l3;
  FUNC_EPILOGUE;
  return i0;
}

static u32 __rg_alloc_zeroed(u32 p0) {
  u32 l1 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  i0 = p0;
  i0 = (*Z_envZ_ext_mallocZ_ii)(i0);
  l1 = i0;
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = l1;
  i1 = 0u;
  i2 = p0;
  i0 = memset_0(i0, i1, i2);
  B0:;
  i0 = l1;
  FUNC_EPILOGUE;
  return i0;
}

static void _ZN4core9panicking5panic17hc8c3dd99127c917dE(u32 p0) {
  u32 l1 = 0;
  u64 l2 = 0, l3 = 0, l4 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  u64 j0, j1;
  i0 = g0;
  i1 = 48u;
  i0 -= i1;
  l1 = i0;
  g0 = i0;
  i0 = p0;
  j0 = i64_load((&memory), (u64)(i0 + 8));
  l2 = j0;
  i0 = p0;
  j0 = i64_load((&memory), (u64)(i0 + 16));
  l3 = j0;
  i0 = p0;
  j0 = i64_load((&memory), (u64)(i0));
  l4 = j0;
  i0 = l1;
  i1 = 20u;
  i0 += i1;
  i1 = 0u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l1;
  j1 = l4;
  i64_store((&memory), (u64)(i0 + 24), j1);
  i0 = l1;
  i1 = 1049368u;
  i32_store((&memory), (u64)(i0 + 16), i1);
  i0 = l1;
  j1 = 1ull;
  i64_store((&memory), (u64)(i0 + 4), j1);
  i0 = l1;
  i1 = l1;
  i2 = 24u;
  i1 += i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l1;
  j1 = l3;
  i64_store((&memory), (u64)(i0 + 40), j1);
  i0 = l1;
  j1 = l2;
  i64_store((&memory), (u64)(i0 + 32), j1);
  i0 = l1;
  i1 = l1;
  i2 = 32u;
  i1 += i2;
  _ZN4core9panicking9panic_fmt17hc562398ea080c8caE(i0, i1);
  UNREACHABLE;
  FUNC_EPILOGUE;
}

static void _ZN4core5slice20slice_index_len_fail17h4903095f5ffa1112E(u32 p0, u32 p1) {
  u32 l2 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  u64 j1;
  i0 = g0;
  i1 = 48u;
  i0 -= i1;
  l2 = i0;
  g0 = i0;
  i0 = l2;
  i1 = p1;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l2;
  i1 = p0;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = 44u;
  i0 += i1;
  i1 = 1u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = 28u;
  i0 += i1;
  i1 = 2u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = 1u;
  i32_store((&memory), (u64)(i0 + 36), i1);
  i0 = l2;
  j1 = 2ull;
  i64_store((&memory), (u64)(i0 + 12), j1);
  i0 = l2;
  i1 = 1049628u;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = l2;
  i1 = l2;
  i2 = 4u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 40), i1);
  i0 = l2;
  i1 = l2;
  i32_store((&memory), (u64)(i0 + 32), i1);
  i0 = l2;
  i1 = l2;
  i2 = 32u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 24), i1);
  i0 = l2;
  i1 = 8u;
  i0 += i1;
  i1 = 1049644u;
  _ZN4core9panicking9panic_fmt17hc562398ea080c8caE(i0, i1);
  UNREACHABLE;
  FUNC_EPILOGUE;
}

static u32 _ZN4core3fmt3num52__LT_impl_u20_core__fmt__Display_u20_for_u20_u32_GT_3fmt17h3f2435e6f3e4ac83E(u32 p0, u32 p1) {
  u32 l2 = 0, l3 = 0, l4 = 0, l5 = 0, l6 = 0, l7 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4, i5;
  i0 = g0;
  i1 = 48u;
  i0 -= i1;
  l2 = i0;
  g0 = i0;
  i0 = 39u;
  l3 = i0;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  p0 = i0;
  i1 = 10000u;
  i0 = i0 < i1;
  if (i0) {goto B5;}
  i0 = 39u;
  l3 = i0;
  L6: 
    i0 = l2;
    i1 = 9u;
    i0 += i1;
    i1 = l3;
    i0 += i1;
    l4 = i0;
    i1 = 4294967292u;
    i0 += i1;
    i1 = p0;
    i2 = p0;
    i3 = 10000u;
    i2 = DIV_U(i2, i3);
    l5 = i2;
    i3 = 4294957296u;
    i2 *= i3;
    i1 += i2;
    l6 = i1;
    i2 = 100u;
    i1 = DIV_U(i1, i2);
    l7 = i1;
    i2 = 1u;
    i1 <<= (i2 & 31);
    i2 = 1048650u;
    i1 += i2;
    i1 = i32_load16_u((&memory), (u64)(i1));
    i32_store16((&memory), (u64)(i0), i1);
    i0 = l4;
    i1 = 4294967294u;
    i0 += i1;
    i1 = l6;
    i2 = l7;
    i3 = 4294967196u;
    i2 *= i3;
    i1 += i2;
    i2 = 1u;
    i1 <<= (i2 & 31);
    i2 = 1048650u;
    i1 += i2;
    i1 = i32_load16_u((&memory), (u64)(i1));
    i32_store16((&memory), (u64)(i0), i1);
    i0 = l3;
    i1 = 4294967292u;
    i0 += i1;
    l3 = i0;
    i0 = p0;
    i1 = 99999999u;
    i0 = i0 > i1;
    l4 = i0;
    i0 = l5;
    p0 = i0;
    i0 = l4;
    if (i0) {goto L6;}
  i0 = 100u;
  l4 = i0;
  i0 = l5;
  i1 = 100u;
  i0 = (u32)((s32)i0 < (s32)i1);
  if (i0) {goto B4;}
  goto B3;
  B5:;
  i0 = 100u;
  l4 = i0;
  i0 = p0;
  l5 = i0;
  i1 = 100u;
  i0 = (u32)((s32)i0 >= (s32)i1);
  if (i0) {goto B3;}
  B4:;
  i0 = l5;
  p0 = i0;
  i1 = 9u;
  i0 = (u32)((s32)i0 > (s32)i1);
  if (i0) {goto B2;}
  goto B1;
  B3:;
  i0 = l2;
  i1 = 9u;
  i0 += i1;
  i1 = l3;
  i2 = 4294967294u;
  i1 += i2;
  l3 = i1;
  i0 += i1;
  i1 = l5;
  i2 = 65535u;
  i1 &= i2;
  i2 = l4;
  i1 = DIV_U(i1, i2);
  p0 = i1;
  i2 = 4294967196u;
  i1 *= i2;
  i2 = l5;
  i1 += i2;
  i2 = 65535u;
  i1 &= i2;
  i2 = 1u;
  i1 <<= (i2 & 31);
  i2 = 1048650u;
  i1 += i2;
  i1 = i32_load16_u((&memory), (u64)(i1));
  i32_store16((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = 9u;
  i0 = (u32)((s32)i0 <= (s32)i1);
  if (i0) {goto B1;}
  B2:;
  i0 = l2;
  i1 = 9u;
  i0 += i1;
  i1 = l3;
  i2 = 4294967294u;
  i1 += i2;
  l3 = i1;
  i0 += i1;
  l5 = i0;
  i1 = p0;
  i2 = 1u;
  i1 <<= (i2 & 31);
  i2 = 1048650u;
  i1 += i2;
  i1 = i32_load16_u((&memory), (u64)(i1));
  i32_store16((&memory), (u64)(i0), i1);
  goto B0;
  B1:;
  i0 = l2;
  i1 = 9u;
  i0 += i1;
  i1 = l3;
  i2 = 4294967295u;
  i1 += i2;
  l3 = i1;
  i0 += i1;
  l5 = i0;
  i1 = p0;
  i2 = 48u;
  i1 += i2;
  i32_store8((&memory), (u64)(i0), i1);
  B0:;
  i0 = p1;
  i1 = 1049368u;
  i2 = 0u;
  i3 = l5;
  i4 = 39u;
  i5 = l3;
  i4 -= i5;
  i0 = _ZN4core3fmt9Formatter12pad_integral17h9a6bb7226e47a2eeE(i0, i1, i2, i3, i4);
  p0 = i0;
  i0 = l2;
  i1 = 48u;
  i0 += i1;
  g0 = i0;
  i0 = p0;
  FUNC_EPILOGUE;
  return i0;
}

static void _ZN4core9panicking9panic_fmt17hc562398ea080c8caE(u32 p0, u32 p1) {
  u32 l2 = 0;
  u64 l3 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1;
  u64 j0, j1;
  i0 = g0;
  i1 = 32u;
  i0 -= i1;
  l2 = i0;
  g0 = i0;
  i0 = p1;
  j0 = i64_load((&memory), (u64)(i0));
  l3 = j0;
  i0 = l2;
  i1 = 20u;
  i0 += i1;
  i1 = p1;
  j1 = i64_load((&memory), (u64)(i1 + 8));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  j1 = l3;
  i64_store((&memory), (u64)(i0 + 12), j1);
  i0 = l2;
  i1 = p0;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = l2;
  i1 = 1049612u;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l2;
  i1 = 1049368u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  rust_begin_unwind(i0);
  UNREACHABLE;
  FUNC_EPILOGUE;
}

static u32 _ZN4core3fmt9Formatter12pad_integral17h9a6bb7226e47a2eeE(u32 p0, u32 p1, u32 p2, u32 p3, u32 p4) {
  u32 l5 = 0, l6 = 0, l7 = 0, l8 = 0, l9 = 0, l10 = 0, l11 = 0, l12 = 0, 
      l13 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4;
  i0 = g0;
  i1 = 16u;
  i0 -= i1;
  l5 = i0;
  g0 = i0;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  l6 = i0;
  i1 = 1u;
  i0 &= i1;
  l7 = i0;
  i1 = p4;
  i0 += i1;
  l8 = i0;
  i0 = l6;
  i1 = 4u;
  i0 &= i1;
  l9 = i0;
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = 0u;
  l10 = i0;
  i0 = p2;
  i0 = !(i0);
  if (i0) {goto B1;}
  i0 = p2;
  l11 = i0;
  i0 = p1;
  l12 = i0;
  L2: 
    i0 = l10;
    i1 = l12;
    i1 = i32_load8_u((&memory), (u64)(i1));
    i2 = 192u;
    i1 &= i2;
    i2 = 128u;
    i1 = i1 == i2;
    i0 += i1;
    l10 = i0;
    i0 = l12;
    i1 = 1u;
    i0 += i1;
    l12 = i0;
    i0 = l11;
    i1 = 4294967295u;
    i0 += i1;
    l11 = i0;
    if (i0) {goto L2;}
  B1:;
  i0 = l8;
  i1 = p2;
  i0 += i1;
  i1 = l10;
  i0 -= i1;
  l8 = i0;
  B0:;
  i0 = 43u;
  i1 = 1114112u;
  i2 = l7;
  i0 = i2 ? i0 : i1;
  l13 = i0;
  i0 = l9;
  i1 = 2u;
  i0 >>= (i1 & 31);
  l9 = i0;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  i1 = 1u;
  i0 = i0 != i1;
  if (i0) {goto B20;}
  i0 = p0;
  i1 = 12u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  l10 = i0;
  i1 = l8;
  i0 = i0 <= i1;
  if (i0) {goto B19;}
  i0 = l6;
  i1 = 8u;
  i0 &= i1;
  if (i0) {goto B18;}
  i0 = l10;
  i1 = l8;
  i0 -= i1;
  l11 = i0;
  i0 = 1u;
  i1 = p0;
  i1 = i32_load8_u((&memory), (u64)(i1 + 48));
  l12 = i1;
  i2 = l12;
  i3 = 3u;
  i2 = i2 == i3;
  i0 = i2 ? i0 : i1;
  i1 = 3u;
  i0 &= i1;
  l12 = i0;
  i0 = !(i0);
  if (i0) {goto B17;}
  i0 = l12;
  i1 = 2u;
  i0 = i0 == i1;
  if (i0) {goto B16;}
  i0 = 0u;
  l8 = i0;
  goto B15;
  B20:;
  i0 = l7;
  i0 = !(i0);
  if (i0) {goto B21;}
  i0 = 1u;
  l12 = i0;
  i0 = p0;
  i1 = 24u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = l13;
  i2 = p0;
  i3 = 28u;
  i2 += i3;
  i2 = i32_load((&memory), (u64)(i2));
  i2 = i32_load((&memory), (u64)(i2 + 16));
  i0 = CALL_INDIRECT(__indirect_function_table, u32 (*)(u32, u32), 0, i2, i0, i1);
  if (i0) {goto B4;}
  B21:;
  i0 = l9;
  i0 = !(i0);
  if (i0) {goto B22;}
  i0 = 1u;
  l12 = i0;
  i0 = p0;
  i1 = 24u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p1;
  i2 = p2;
  i3 = p0;
  i4 = 28u;
  i3 += i4;
  i3 = i32_load((&memory), (u64)(i3));
  i3 = i32_load((&memory), (u64)(i3 + 12));
  i0 = CALL_INDIRECT(__indirect_function_table, u32 (*)(u32, u32, u32), 1, i3, i0, i1, i2);
  if (i0) {goto B4;}
  B22:;
  i0 = p0;
  i1 = 24u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p3;
  i2 = p4;
  i3 = p0;
  i4 = 28u;
  i3 += i4;
  i3 = i32_load((&memory), (u64)(i3));
  i3 = i32_load((&memory), (u64)(i3 + 12));
  i0 = CALL_INDIRECT(__indirect_function_table, u32 (*)(u32, u32, u32), 1, i3, i0, i1, i2);
  l12 = i0;
  i0 = l5;
  i1 = 16u;
  i0 += i1;
  g0 = i0;
  i0 = l12;
  goto Bfunc;
  B19:;
  i0 = l7;
  i0 = !(i0);
  if (i0) {goto B23;}
  i0 = 1u;
  l12 = i0;
  i0 = p0;
  i1 = 24u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = l13;
  i2 = p0;
  i3 = 28u;
  i2 += i3;
  i2 = i32_load((&memory), (u64)(i2));
  i2 = i32_load((&memory), (u64)(i2 + 16));
  i0 = CALL_INDIRECT(__indirect_function_table, u32 (*)(u32, u32), 0, i2, i0, i1);
  if (i0) {goto B4;}
  B23:;
  i0 = l9;
  i0 = !(i0);
  if (i0) {goto B24;}
  i0 = 1u;
  l12 = i0;
  i0 = p0;
  i1 = 24u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p1;
  i2 = p2;
  i3 = p0;
  i4 = 28u;
  i3 += i4;
  i3 = i32_load((&memory), (u64)(i3));
  i3 = i32_load((&memory), (u64)(i3 + 12));
  i0 = CALL_INDIRECT(__indirect_function_table, u32 (*)(u32, u32, u32), 1, i3, i0, i1, i2);
  if (i0) {goto B4;}
  B24:;
  i0 = p0;
  i1 = 24u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p3;
  i2 = p4;
  i3 = p0;
  i4 = 28u;
  i3 += i4;
  i3 = i32_load((&memory), (u64)(i3));
  i3 = i32_load((&memory), (u64)(i3 + 12));
  i0 = CALL_INDIRECT(__indirect_function_table, u32 (*)(u32, u32, u32), 1, i3, i0, i1, i2);
  l12 = i0;
  i0 = l5;
  i1 = 16u;
  i0 += i1;
  g0 = i0;
  i0 = l12;
  goto Bfunc;
  B18:;
  i0 = 1u;
  l12 = i0;
  i0 = p0;
  i1 = 1u;
  i32_store8((&memory), (u64)(i0 + 48), i1);
  i0 = p0;
  i1 = 48u;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l7;
  i0 = !(i0);
  if (i0) {goto B25;}
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 24));
  i1 = l13;
  i2 = p0;
  i3 = 28u;
  i2 += i3;
  i2 = i32_load((&memory), (u64)(i2));
  i2 = i32_load((&memory), (u64)(i2 + 16));
  i0 = CALL_INDIRECT(__indirect_function_table, u32 (*)(u32, u32), 0, i2, i0, i1);
  if (i0) {goto B4;}
  B25:;
  i0 = l9;
  i0 = !(i0);
  if (i0) {goto B26;}
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 24));
  i1 = p1;
  i2 = p2;
  i3 = p0;
  i4 = 28u;
  i3 += i4;
  i3 = i32_load((&memory), (u64)(i3));
  i3 = i32_load((&memory), (u64)(i3 + 12));
  i0 = CALL_INDIRECT(__indirect_function_table, u32 (*)(u32, u32, u32), 1, i3, i0, i1, i2);
  if (i0) {goto B4;}
  B26:;
  i0 = l10;
  i1 = l8;
  i0 -= i1;
  l11 = i0;
  i0 = 1u;
  i1 = p0;
  i2 = 48u;
  i1 += i2;
  i1 = i32_load8_u((&memory), (u64)(i1));
  l12 = i1;
  i2 = l12;
  i3 = 3u;
  i2 = i2 == i3;
  i0 = i2 ? i0 : i1;
  i1 = 3u;
  i0 &= i1;
  l12 = i0;
  i0 = !(i0);
  if (i0) {goto B13;}
  i0 = l12;
  i1 = 2u;
  i0 = i0 == i1;
  if (i0) {goto B14;}
  i0 = 0u;
  l7 = i0;
  goto B12;
  B17:;
  i0 = l11;
  l8 = i0;
  i0 = 0u;
  l11 = i0;
  goto B15;
  B16:;
  i0 = l11;
  i1 = 1u;
  i0 += i1;
  i1 = 1u;
  i0 >>= (i1 & 31);
  l8 = i0;
  i0 = l11;
  i1 = 1u;
  i0 >>= (i1 & 31);
  l11 = i0;
  B15:;
  i0 = l5;
  i1 = 0u;
  i32_store((&memory), (u64)(i0 + 12), i1);
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l12 = i0;
  i1 = 127u;
  i0 = i0 > i1;
  if (i0) {goto B27;}
  i0 = l5;
  i1 = l12;
  i32_store8((&memory), (u64)(i0 + 12), i1);
  i0 = 1u;
  l10 = i0;
  goto B10;
  B27:;
  i0 = l12;
  i1 = 2047u;
  i0 = i0 > i1;
  if (i0) {goto B28;}
  i0 = l5;
  i1 = l12;
  i2 = 63u;
  i1 &= i2;
  i2 = 128u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 13), i1);
  i0 = l5;
  i1 = l12;
  i2 = 6u;
  i1 >>= (i2 & 31);
  i2 = 31u;
  i1 &= i2;
  i2 = 192u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 12), i1);
  i0 = 2u;
  l10 = i0;
  goto B10;
  B28:;
  i0 = l12;
  i1 = 65535u;
  i0 = i0 > i1;
  if (i0) {goto B11;}
  i0 = l5;
  i1 = l12;
  i2 = 63u;
  i1 &= i2;
  i2 = 128u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 14), i1);
  i0 = l5;
  i1 = l12;
  i2 = 6u;
  i1 >>= (i2 & 31);
  i2 = 63u;
  i1 &= i2;
  i2 = 128u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 13), i1);
  i0 = l5;
  i1 = l12;
  i2 = 12u;
  i1 >>= (i2 & 31);
  i2 = 15u;
  i1 &= i2;
  i2 = 224u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 12), i1);
  i0 = 3u;
  l10 = i0;
  goto B10;
  B14:;
  i0 = l11;
  i1 = 1u;
  i0 += i1;
  i1 = 1u;
  i0 >>= (i1 & 31);
  l7 = i0;
  i0 = l11;
  i1 = 1u;
  i0 >>= (i1 & 31);
  l11 = i0;
  goto B12;
  B13:;
  i0 = l11;
  l7 = i0;
  i0 = 0u;
  l11 = i0;
  B12:;
  i0 = l5;
  i1 = 0u;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = p0;
  i1 = 4u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  l12 = i0;
  i1 = 127u;
  i0 = i0 > i1;
  if (i0) {goto B29;}
  i0 = l5;
  i1 = l12;
  i32_store8((&memory), (u64)(i0 + 8), i1);
  i0 = 1u;
  l10 = i0;
  goto B6;
  B29:;
  i0 = l12;
  i1 = 2047u;
  i0 = i0 > i1;
  if (i0) {goto B9;}
  i0 = l5;
  i1 = l12;
  i2 = 63u;
  i1 &= i2;
  i2 = 128u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 9), i1);
  i0 = l5;
  i1 = l12;
  i2 = 6u;
  i1 >>= (i2 & 31);
  i2 = 31u;
  i1 &= i2;
  i2 = 192u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 8), i1);
  i0 = 2u;
  l10 = i0;
  goto B6;
  B11:;
  i0 = l5;
  i1 = l12;
  i2 = 63u;
  i1 &= i2;
  i2 = 128u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 15), i1);
  i0 = l5;
  i1 = l12;
  i2 = 18u;
  i1 >>= (i2 & 31);
  i2 = 240u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 12), i1);
  i0 = l5;
  i1 = l12;
  i2 = 6u;
  i1 >>= (i2 & 31);
  i2 = 63u;
  i1 &= i2;
  i2 = 128u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 14), i1);
  i0 = l5;
  i1 = l12;
  i2 = 12u;
  i1 >>= (i2 & 31);
  i2 = 63u;
  i1 &= i2;
  i2 = 128u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 13), i1);
  i0 = 4u;
  l10 = i0;
  B10:;
  i0 = 4294967295u;
  l12 = i0;
  L31: 
    i0 = l12;
    i1 = 1u;
    i0 += i1;
    l12 = i0;
    i1 = l11;
    i0 = i0 >= i1;
    if (i0) {goto B30;}
    i0 = p0;
    i1 = 24u;
    i0 += i1;
    i0 = i32_load((&memory), (u64)(i0));
    i1 = l5;
    i2 = 12u;
    i1 += i2;
    i2 = l10;
    i3 = p0;
    i4 = 28u;
    i3 += i4;
    i3 = i32_load((&memory), (u64)(i3));
    i3 = i32_load((&memory), (u64)(i3 + 12));
    i0 = CALL_INDIRECT(__indirect_function_table, u32 (*)(u32, u32, u32), 1, i3, i0, i1, i2);
    i0 = !(i0);
    if (i0) {goto L31;}
    goto B5;
  B30:;
  i0 = l7;
  i0 = !(i0);
  if (i0) {goto B32;}
  i0 = p0;
  i1 = 24u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = l13;
  i2 = p0;
  i3 = 28u;
  i2 += i3;
  i2 = i32_load((&memory), (u64)(i2));
  i2 = i32_load((&memory), (u64)(i2 + 16));
  i0 = CALL_INDIRECT(__indirect_function_table, u32 (*)(u32, u32), 0, i2, i0, i1);
  if (i0) {goto B5;}
  B32:;
  i0 = l9;
  i0 = !(i0);
  if (i0) {goto B33;}
  i0 = p0;
  i1 = 24u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p1;
  i2 = p2;
  i3 = p0;
  i4 = 28u;
  i3 += i4;
  i3 = i32_load((&memory), (u64)(i3));
  i3 = i32_load((&memory), (u64)(i3 + 12));
  i0 = CALL_INDIRECT(__indirect_function_table, u32 (*)(u32, u32, u32), 1, i3, i0, i1, i2);
  if (i0) {goto B5;}
  B33:;
  i0 = p0;
  i1 = 24u;
  i0 += i1;
  l11 = i0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p3;
  i2 = p4;
  i3 = p0;
  i4 = 28u;
  i3 += i4;
  p0 = i3;
  i3 = i32_load((&memory), (u64)(i3));
  i3 = i32_load((&memory), (u64)(i3 + 12));
  i0 = CALL_INDIRECT(__indirect_function_table, u32 (*)(u32, u32, u32), 1, i3, i0, i1, i2);
  if (i0) {goto B5;}
  i0 = 4294967295u;
  l12 = i0;
  L34: 
    i0 = l12;
    i1 = 1u;
    i0 += i1;
    l12 = i0;
    i1 = l8;
    i0 = i0 >= i1;
    if (i0) {goto B8;}
    i0 = l11;
    i0 = i32_load((&memory), (u64)(i0));
    i1 = l5;
    i2 = 12u;
    i1 += i2;
    i2 = l10;
    i3 = p0;
    i3 = i32_load((&memory), (u64)(i3));
    i3 = i32_load((&memory), (u64)(i3 + 12));
    i0 = CALL_INDIRECT(__indirect_function_table, u32 (*)(u32, u32, u32), 1, i3, i0, i1, i2);
    i0 = !(i0);
    if (i0) {goto L34;}
    goto B5;
  B9:;
  i0 = l12;
  i1 = 65535u;
  i0 = i0 > i1;
  if (i0) {goto B7;}
  i0 = l5;
  i1 = l12;
  i2 = 63u;
  i1 &= i2;
  i2 = 128u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 10), i1);
  i0 = l5;
  i1 = l12;
  i2 = 6u;
  i1 >>= (i2 & 31);
  i2 = 63u;
  i1 &= i2;
  i2 = 128u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 9), i1);
  i0 = l5;
  i1 = l12;
  i2 = 12u;
  i1 >>= (i2 & 31);
  i2 = 15u;
  i1 &= i2;
  i2 = 224u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 8), i1);
  i0 = 3u;
  l10 = i0;
  goto B6;
  B8:;
  i0 = l5;
  i1 = 16u;
  i0 += i1;
  g0 = i0;
  i0 = 0u;
  goto Bfunc;
  B7:;
  i0 = l5;
  i1 = l12;
  i2 = 63u;
  i1 &= i2;
  i2 = 128u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 11), i1);
  i0 = l5;
  i1 = l12;
  i2 = 18u;
  i1 >>= (i2 & 31);
  i2 = 240u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 8), i1);
  i0 = l5;
  i1 = l12;
  i2 = 6u;
  i1 >>= (i2 & 31);
  i2 = 63u;
  i1 &= i2;
  i2 = 128u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 10), i1);
  i0 = l5;
  i1 = l12;
  i2 = 12u;
  i1 >>= (i2 & 31);
  i2 = 63u;
  i1 &= i2;
  i2 = 128u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 9), i1);
  i0 = 4u;
  l10 = i0;
  B6:;
  i0 = 4294967295u;
  l12 = i0;
  L36: 
    i0 = l12;
    i1 = 1u;
    i0 += i1;
    l12 = i0;
    i1 = l11;
    i0 = i0 >= i1;
    if (i0) {goto B35;}
    i0 = p0;
    i1 = 24u;
    i0 += i1;
    i0 = i32_load((&memory), (u64)(i0));
    i1 = l5;
    i2 = 8u;
    i1 += i2;
    i2 = l10;
    i3 = p0;
    i4 = 28u;
    i3 += i4;
    i3 = i32_load((&memory), (u64)(i3));
    i3 = i32_load((&memory), (u64)(i3 + 12));
    i0 = CALL_INDIRECT(__indirect_function_table, u32 (*)(u32, u32, u32), 1, i3, i0, i1, i2);
    i0 = !(i0);
    if (i0) {goto L36;}
    goto B5;
  B35:;
  i0 = p0;
  i1 = 24u;
  i0 += i1;
  l11 = i0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p3;
  i2 = p4;
  i3 = p0;
  i4 = 28u;
  i3 += i4;
  p0 = i3;
  i3 = i32_load((&memory), (u64)(i3));
  i3 = i32_load((&memory), (u64)(i3 + 12));
  i0 = CALL_INDIRECT(__indirect_function_table, u32 (*)(u32, u32, u32), 1, i3, i0, i1, i2);
  if (i0) {goto B5;}
  i0 = 4294967295u;
  l12 = i0;
  L37: 
    i0 = l12;
    i1 = 1u;
    i0 += i1;
    l12 = i0;
    i1 = l7;
    i0 = i0 >= i1;
    if (i0) {goto B3;}
    i0 = l11;
    i0 = i32_load((&memory), (u64)(i0));
    i1 = l5;
    i2 = 8u;
    i1 += i2;
    i2 = l10;
    i3 = p0;
    i3 = i32_load((&memory), (u64)(i3));
    i3 = i32_load((&memory), (u64)(i3 + 12));
    i0 = CALL_INDIRECT(__indirect_function_table, u32 (*)(u32, u32, u32), 1, i3, i0, i1, i2);
    i0 = !(i0);
    if (i0) {goto L37;}
  B5:;
  i0 = 1u;
  l12 = i0;
  B4:;
  i0 = l5;
  i1 = 16u;
  i0 += i1;
  g0 = i0;
  i0 = l12;
  goto Bfunc;
  B3:;
  i0 = l5;
  i1 = 16u;
  i0 += i1;
  g0 = i0;
  i0 = 0u;
  Bfunc:;
  FUNC_EPILOGUE;
  return i0;
}

static void _ZN4core3ptr18real_drop_in_place17h73c609b348f6cf67E(u32 p0) {
  FUNC_PROLOGUE;
  FUNC_EPILOGUE;
}

static u64 _ZN36__LT_T_u20_as_u20_core__any__Any_GT_11get_type_id17h1457de5e51092096E(u32 p0) {
  FUNC_PROLOGUE;
  u64 j0;
  j0 = 40975079623160374ull;
  FUNC_EPILOGUE;
  return j0;
}

static u32 _ZN4core3fmt9Formatter3pad17h8572ace509bf2797E(u32 p0, u32 p1, u32 p2) {
  u32 l3 = 0, l4 = 0, l5 = 0, l6 = 0, l7 = 0, l8 = 0, l9 = 0, l10 = 0, 
      l11 = 0, l12 = 0, l13 = 0, l14 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4;
  i0 = g0;
  i1 = 16u;
  i0 -= i1;
  l3 = i0;
  g0 = i0;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 16));
  l4 = i0;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  l5 = i0;
  i1 = 1u;
  i0 = i0 != i1;
  if (i0) {goto B8;}
  i0 = l4;
  if (i0) {goto B7;}
  goto B6;
  B8:;
  i0 = l4;
  i0 = !(i0);
  if (i0) {goto B0;}
  B7:;
  i0 = p2;
  i0 = !(i0);
  if (i0) {goto B9;}
  i0 = p1;
  i1 = p2;
  i0 += i1;
  l6 = i0;
  i0 = p0;
  i1 = 20u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = 4294967295u;
  i0 ^= i1;
  l7 = i0;
  i0 = 0u;
  l8 = i0;
  i0 = p1;
  l4 = i0;
  i0 = p1;
  l9 = i0;
  L12: 
    i0 = l4;
    i1 = 1u;
    i0 += i1;
    l10 = i0;
    i0 = l4;
    i0 = i32_load8_s((&memory), (u64)(i0));
    l11 = i0;
    i1 = 0u;
    i0 = (u32)((s32)i0 < (s32)i1);
    if (i0) {goto B14;}
    i0 = l11;
    i1 = 255u;
    i0 &= i1;
    l11 = i0;
    i0 = l10;
    l4 = i0;
    i0 = l7;
    i1 = 1u;
    i0 += i1;
    l7 = i0;
    if (i0) {goto B13;}
    goto B11;
    B14:;
    i0 = l10;
    i1 = l6;
    i0 = i0 == i1;
    if (i0) {goto B17;}
    i0 = l10;
    i0 = i32_load8_u((&memory), (u64)(i0));
    i1 = 63u;
    i0 &= i1;
    l12 = i0;
    i0 = l4;
    i1 = 2u;
    i0 += i1;
    l4 = i0;
    l10 = i0;
    i0 = l11;
    i1 = 31u;
    i0 &= i1;
    l13 = i0;
    i0 = l11;
    i1 = 255u;
    i0 &= i1;
    l11 = i0;
    i1 = 224u;
    i0 = i0 < i1;
    if (i0) {goto B16;}
    goto B15;
    B17:;
    i0 = 0u;
    l12 = i0;
    i0 = l6;
    l4 = i0;
    i0 = l11;
    i1 = 31u;
    i0 &= i1;
    l13 = i0;
    i0 = l11;
    i1 = 255u;
    i0 &= i1;
    l11 = i0;
    i1 = 224u;
    i0 = i0 >= i1;
    if (i0) {goto B15;}
    B16:;
    i0 = l12;
    i1 = l13;
    i2 = 6u;
    i1 <<= (i2 & 31);
    i0 |= i1;
    l11 = i0;
    i0 = l10;
    l4 = i0;
    i0 = l7;
    i1 = 1u;
    i0 += i1;
    l7 = i0;
    if (i0) {goto B13;}
    goto B11;
    B15:;
    i0 = l4;
    i1 = l6;
    i0 = i0 == i1;
    if (i0) {goto B20;}
    i0 = l4;
    i1 = 1u;
    i0 += i1;
    l10 = i0;
    l14 = i0;
    i0 = l4;
    i0 = i32_load8_u((&memory), (u64)(i0));
    i1 = 63u;
    i0 &= i1;
    i1 = l12;
    i2 = 6u;
    i1 <<= (i2 & 31);
    i0 |= i1;
    l12 = i0;
    i0 = l11;
    i1 = 240u;
    i0 = i0 < i1;
    if (i0) {goto B19;}
    goto B18;
    B20:;
    i0 = l6;
    l14 = i0;
    i0 = 0u;
    i1 = l12;
    i2 = 6u;
    i1 <<= (i2 & 31);
    i0 |= i1;
    l12 = i0;
    i0 = l11;
    i1 = 240u;
    i0 = i0 >= i1;
    if (i0) {goto B18;}
    B19:;
    i0 = l12;
    i1 = l13;
    i2 = 12u;
    i1 <<= (i2 & 31);
    i0 |= i1;
    l11 = i0;
    i0 = l10;
    l4 = i0;
    i0 = l7;
    i1 = 1u;
    i0 += i1;
    l7 = i0;
    if (i0) {goto B13;}
    goto B11;
    B18:;
    i0 = l14;
    i1 = l6;
    i0 = i0 == i1;
    if (i0) {goto B22;}
    i0 = l14;
    i1 = 1u;
    i0 += i1;
    l4 = i0;
    i0 = l14;
    i0 = i32_load8_u((&memory), (u64)(i0));
    i1 = 63u;
    i0 &= i1;
    l11 = i0;
    goto B21;
    B22:;
    i0 = 0u;
    l11 = i0;
    i0 = l10;
    l4 = i0;
    B21:;
    i0 = l12;
    i1 = 6u;
    i0 <<= (i1 & 31);
    i1 = l13;
    i2 = 18u;
    i1 <<= (i2 & 31);
    i2 = 1835008u;
    i1 &= i2;
    i0 |= i1;
    i1 = l11;
    i0 |= i1;
    l11 = i0;
    i1 = 1114112u;
    i0 = i0 == i1;
    if (i0) {goto B10;}
    i0 = l7;
    i1 = 1u;
    i0 += i1;
    l7 = i0;
    i0 = !(i0);
    if (i0) {goto B11;}
    B13:;
    i0 = l8;
    i1 = l9;
    i0 -= i1;
    i1 = l4;
    i0 += i1;
    l8 = i0;
    i0 = l4;
    l9 = i0;
    i0 = l6;
    i1 = l4;
    i0 = i0 != i1;
    if (i0) {goto L12;}
    goto B10;
  B11:;
  i0 = l11;
  i1 = 1114112u;
  i0 = i0 == i1;
  if (i0) {goto B10;}
  i0 = l8;
  i0 = !(i0);
  if (i0) {goto B24;}
  i0 = l8;
  i1 = p2;
  i0 = i0 == i1;
  if (i0) {goto B24;}
  i0 = 0u;
  l4 = i0;
  i0 = l8;
  i1 = p2;
  i0 = i0 >= i1;
  if (i0) {goto B23;}
  i0 = p1;
  i1 = l8;
  i0 += i1;
  i0 = i32_load8_s((&memory), (u64)(i0));
  i1 = 4294967232u;
  i0 = (u32)((s32)i0 < (s32)i1);
  if (i0) {goto B23;}
  B24:;
  i0 = p1;
  l4 = i0;
  B23:;
  i0 = l8;
  i1 = p2;
  i2 = l4;
  i0 = i2 ? i0 : i1;
  p2 = i0;
  i0 = l4;
  i1 = p1;
  i2 = l4;
  i0 = i2 ? i0 : i1;
  p1 = i0;
  B10:;
  i0 = l5;
  i0 = !(i0);
  if (i0) {goto B5;}
  goto B6;
  B9:;
  i0 = 0u;
  p2 = i0;
  i0 = l5;
  i0 = !(i0);
  if (i0) {goto B5;}
  B6:;
  i0 = 0u;
  l10 = i0;
  i0 = p2;
  i0 = !(i0);
  if (i0) {goto B25;}
  i0 = p2;
  l11 = i0;
  i0 = p1;
  l4 = i0;
  L26: 
    i0 = l10;
    i1 = l4;
    i1 = i32_load8_u((&memory), (u64)(i1));
    i2 = 192u;
    i1 &= i2;
    i2 = 128u;
    i1 = i1 == i2;
    i0 += i1;
    l10 = i0;
    i0 = l4;
    i1 = 1u;
    i0 += i1;
    l4 = i0;
    i0 = l11;
    i1 = 4294967295u;
    i0 += i1;
    l11 = i0;
    if (i0) {goto L26;}
  B25:;
  i0 = p2;
  i1 = l10;
  i0 -= i1;
  i1 = p0;
  i2 = 12u;
  i1 += i2;
  i1 = i32_load((&memory), (u64)(i1));
  l7 = i1;
  i0 = i0 >= i1;
  if (i0) {goto B4;}
  i0 = 0u;
  l10 = i0;
  i0 = p2;
  i0 = !(i0);
  if (i0) {goto B27;}
  i0 = 0u;
  l10 = i0;
  i0 = p2;
  l11 = i0;
  i0 = p1;
  l4 = i0;
  L28: 
    i0 = l10;
    i1 = l4;
    i1 = i32_load8_u((&memory), (u64)(i1));
    i2 = 192u;
    i1 &= i2;
    i2 = 128u;
    i1 = i1 == i2;
    i0 += i1;
    l10 = i0;
    i0 = l4;
    i1 = 1u;
    i0 += i1;
    l4 = i0;
    i0 = l11;
    i1 = 4294967295u;
    i0 += i1;
    l11 = i0;
    if (i0) {goto L28;}
  B27:;
  i0 = l10;
  i1 = p2;
  i0 -= i1;
  i1 = l7;
  i0 += i1;
  l11 = i0;
  i0 = 0u;
  i1 = p0;
  i1 = i32_load8_u((&memory), (u64)(i1 + 48));
  l4 = i1;
  i2 = l4;
  i3 = 3u;
  i2 = i2 == i3;
  i0 = i2 ? i0 : i1;
  i1 = 3u;
  i0 &= i1;
  l4 = i0;
  i0 = !(i0);
  if (i0) {goto B3;}
  i0 = l4;
  i1 = 2u;
  i0 = i0 == i1;
  if (i0) {goto B2;}
  i0 = 0u;
  l7 = i0;
  goto B1;
  B5:;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 24));
  i1 = p1;
  i2 = p2;
  i3 = p0;
  i4 = 28u;
  i3 += i4;
  i3 = i32_load((&memory), (u64)(i3));
  i3 = i32_load((&memory), (u64)(i3 + 12));
  i0 = CALL_INDIRECT(__indirect_function_table, u32 (*)(u32, u32, u32), 1, i3, i0, i1, i2);
  l4 = i0;
  i0 = l3;
  i1 = 16u;
  i0 += i1;
  g0 = i0;
  i0 = l4;
  goto Bfunc;
  B4:;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 24));
  i1 = p1;
  i2 = p2;
  i3 = p0;
  i4 = 28u;
  i3 += i4;
  i3 = i32_load((&memory), (u64)(i3));
  i3 = i32_load((&memory), (u64)(i3 + 12));
  i0 = CALL_INDIRECT(__indirect_function_table, u32 (*)(u32, u32, u32), 1, i3, i0, i1, i2);
  l4 = i0;
  i0 = l3;
  i1 = 16u;
  i0 += i1;
  g0 = i0;
  i0 = l4;
  goto Bfunc;
  B3:;
  i0 = l11;
  l7 = i0;
  i0 = 0u;
  l11 = i0;
  goto B1;
  B2:;
  i0 = l11;
  i1 = 1u;
  i0 += i1;
  i1 = 1u;
  i0 >>= (i1 & 31);
  l7 = i0;
  i0 = l11;
  i1 = 1u;
  i0 >>= (i1 & 31);
  l11 = i0;
  B1:;
  i0 = l3;
  i1 = 0u;
  i32_store((&memory), (u64)(i0 + 12), i1);
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l4 = i0;
  i1 = 127u;
  i0 = i0 > i1;
  if (i0) {goto B30;}
  i0 = l3;
  i1 = l4;
  i32_store8((&memory), (u64)(i0 + 12), i1);
  i0 = 1u;
  l10 = i0;
  goto B29;
  B30:;
  i0 = l4;
  i1 = 2047u;
  i0 = i0 > i1;
  if (i0) {goto B31;}
  i0 = l3;
  i1 = l4;
  i2 = 63u;
  i1 &= i2;
  i2 = 128u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 13), i1);
  i0 = l3;
  i1 = l4;
  i2 = 6u;
  i1 >>= (i2 & 31);
  i2 = 31u;
  i1 &= i2;
  i2 = 192u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 12), i1);
  i0 = 2u;
  l10 = i0;
  goto B29;
  B31:;
  i0 = l4;
  i1 = 65535u;
  i0 = i0 > i1;
  if (i0) {goto B32;}
  i0 = l3;
  i1 = l4;
  i2 = 63u;
  i1 &= i2;
  i2 = 128u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 14), i1);
  i0 = l3;
  i1 = l4;
  i2 = 6u;
  i1 >>= (i2 & 31);
  i2 = 63u;
  i1 &= i2;
  i2 = 128u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 13), i1);
  i0 = l3;
  i1 = l4;
  i2 = 12u;
  i1 >>= (i2 & 31);
  i2 = 15u;
  i1 &= i2;
  i2 = 224u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 12), i1);
  i0 = 3u;
  l10 = i0;
  goto B29;
  B32:;
  i0 = l3;
  i1 = l4;
  i2 = 63u;
  i1 &= i2;
  i2 = 128u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 15), i1);
  i0 = l3;
  i1 = l4;
  i2 = 18u;
  i1 >>= (i2 & 31);
  i2 = 240u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 12), i1);
  i0 = l3;
  i1 = l4;
  i2 = 6u;
  i1 >>= (i2 & 31);
  i2 = 63u;
  i1 &= i2;
  i2 = 128u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 14), i1);
  i0 = l3;
  i1 = l4;
  i2 = 12u;
  i1 >>= (i2 & 31);
  i2 = 63u;
  i1 &= i2;
  i2 = 128u;
  i1 |= i2;
  i32_store8((&memory), (u64)(i0 + 13), i1);
  i0 = 4u;
  l10 = i0;
  B29:;
  i0 = 4294967295u;
  l4 = i0;
  L36: 
    i0 = l4;
    i1 = 1u;
    i0 += i1;
    l4 = i0;
    i1 = l11;
    i0 = i0 >= i1;
    if (i0) {goto B35;}
    i0 = p0;
    i1 = 24u;
    i0 += i1;
    i0 = i32_load((&memory), (u64)(i0));
    i1 = l3;
    i2 = 12u;
    i1 += i2;
    i2 = l10;
    i3 = p0;
    i4 = 28u;
    i3 += i4;
    i3 = i32_load((&memory), (u64)(i3));
    i3 = i32_load((&memory), (u64)(i3 + 12));
    i0 = CALL_INDIRECT(__indirect_function_table, u32 (*)(u32, u32, u32), 1, i3, i0, i1, i2);
    i0 = !(i0);
    if (i0) {goto L36;}
    goto B34;
  B35:;
  i0 = p0;
  i1 = 24u;
  i0 += i1;
  l11 = i0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p1;
  i2 = p2;
  i3 = p0;
  i4 = 28u;
  i3 += i4;
  p0 = i3;
  i3 = i32_load((&memory), (u64)(i3));
  i3 = i32_load((&memory), (u64)(i3 + 12));
  i0 = CALL_INDIRECT(__indirect_function_table, u32 (*)(u32, u32, u32), 1, i3, i0, i1, i2);
  i0 = !(i0);
  if (i0) {goto B33;}
  B34:;
  i0 = l3;
  i1 = 16u;
  i0 += i1;
  g0 = i0;
  i0 = 1u;
  goto Bfunc;
  B33:;
  i0 = 4294967295u;
  l4 = i0;
  L38: 
    i0 = l4;
    i1 = 1u;
    i0 += i1;
    l4 = i0;
    i1 = l7;
    i0 = i0 >= i1;
    if (i0) {goto B37;}
    i0 = l11;
    i0 = i32_load((&memory), (u64)(i0));
    i1 = l3;
    i2 = 12u;
    i1 += i2;
    i2 = l10;
    i3 = p0;
    i3 = i32_load((&memory), (u64)(i3));
    i3 = i32_load((&memory), (u64)(i3 + 12));
    i0 = CALL_INDIRECT(__indirect_function_table, u32 (*)(u32, u32, u32), 1, i3, i0, i1, i2);
    i0 = !(i0);
    if (i0) {goto L38;}
  i0 = l3;
  i1 = 16u;
  i0 += i1;
  g0 = i0;
  i0 = 1u;
  goto Bfunc;
  B37:;
  i0 = l3;
  i1 = 16u;
  i0 += i1;
  g0 = i0;
  i0 = 0u;
  goto Bfunc;
  B0:;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 24));
  i1 = p1;
  i2 = p2;
  i3 = p0;
  i4 = 28u;
  i3 += i4;
  i3 = i32_load((&memory), (u64)(i3));
  i3 = i32_load((&memory), (u64)(i3 + 12));
  i0 = CALL_INDIRECT(__indirect_function_table, u32 (*)(u32, u32, u32), 1, i3, i0, i1, i2);
  l4 = i0;
  i0 = l3;
  i1 = 16u;
  i0 += i1;
  g0 = i0;
  i0 = l4;
  Bfunc:;
  FUNC_EPILOGUE;
  return i0;
}

static void _ZN4core6option13expect_failed17he3f99b0653a0c0b7E(void) {
  u32 l0 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  u64 j1;
  i0 = g0;
  i1 = 48u;
  i0 -= i1;
  l0 = i0;
  g0 = i0;
  i0 = l0;
  i1 = 112u;
  i32_store((&memory), (u64)(i0 + 12), i1);
  i0 = l0;
  i1 = 1049368u;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = l0;
  i1 = 36u;
  i0 += i1;
  i1 = 1u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l0;
  i1 = 2u;
  i32_store((&memory), (u64)(i0 + 44), i1);
  i0 = l0;
  j1 = 1ull;
  i64_store((&memory), (u64)(i0 + 20), j1);
  i0 = l0;
  i1 = 1049692u;
  i32_store((&memory), (u64)(i0 + 16), i1);
  i0 = l0;
  i1 = l0;
  i2 = 8u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 40), i1);
  i0 = l0;
  i1 = l0;
  i2 = 40u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 32), i1);
  i0 = l0;
  i1 = 16u;
  i0 += i1;
  i1 = 1049700u;
  _ZN4core9panicking9panic_fmt17hc562398ea080c8caE(i0, i1);
  UNREACHABLE;
  FUNC_EPILOGUE;
}

static u32 _ZN44__LT__RF_T_u20_as_u20_core__fmt__Display_GT_3fmt17h01b6108549776650E(u32 p0, u32 p1) {
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  i0 = p1;
  i1 = p0;
  i1 = i32_load((&memory), (u64)(i1));
  i2 = p0;
  i2 = i32_load((&memory), (u64)(i2 + 4));
  i0 = _ZN4core3fmt9Formatter3pad17h8572ace509bf2797E(i0, i1, i2);
  FUNC_EPILOGUE;
  return i0;
}

static u32 __rust_alloc_zeroed(u32 p0) {
  FUNC_PROLOGUE;
  u32 i0;
  i0 = p0;
  i0 = __rg_alloc_zeroed(i0);
  FUNC_EPILOGUE;
  return i0;
}

static void _ZN12parity_codec5codec6Encode6encode17h7199eee6cd6e7a2fE(u32 p0, u32 p1) {
  u32 l2 = 0, l3 = 0, l4 = 0, l5 = 0, l6 = 0, l7 = 0, l8 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  u64 j1;
  i0 = g0;
  i1 = 16u;
  i0 -= i1;
  l2 = i0;
  g0 = i0;
  i0 = l2;
  i1 = 0u;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = l2;
  j1 = 1ull;
  i64_store((&memory), (u64)(i0), j1);
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0));
  l3 = i0;
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  p1 = i0;
  i1 = 63u;
  i0 = i0 > i1;
  if (i0) {goto B12;}
  i0 = 1u;
  i0 = __rust_alloc(i0);
  l4 = i0;
  i0 = !(i0);
  if (i0) {goto B4;}
  i0 = l2;
  i1 = 1u;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l2;
  i1 = 8u;
  i0 += i1;
  l5 = i0;
  i1 = l5;
  i1 = i32_load((&memory), (u64)(i1));
  l5 = i1;
  i2 = 1u;
  i1 += i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = l4;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l4;
  i1 = l5;
  i0 += i1;
  i1 = p1;
  i2 = 2u;
  i1 <<= (i2 & 31);
  i32_store8((&memory), (u64)(i0), i1);
  i0 = p1;
  if (i0) {goto B11;}
  goto B10;
  B12:;
  i0 = p1;
  i1 = 16384u;
  i0 = i0 >= i1;
  if (i0) {goto B13;}
  i0 = 2u;
  i0 = __rust_alloc(i0);
  l4 = i0;
  i0 = !(i0);
  if (i0) {goto B3;}
  i0 = l2;
  i1 = 2u;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l2;
  i1 = 8u;
  i0 += i1;
  l5 = i0;
  i1 = l5;
  i1 = i32_load((&memory), (u64)(i1));
  l5 = i1;
  i2 = 2u;
  i1 += i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = l4;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l4;
  i1 = l5;
  i0 += i1;
  i1 = p1;
  i2 = 2u;
  i1 <<= (i2 & 31);
  i2 = 1u;
  i1 |= i2;
  i32_store16((&memory), (u64)(i0), i1);
  goto B11;
  B13:;
  i0 = p1;
  i1 = 1073741824u;
  i0 = i0 >= i1;
  if (i0) {goto B14;}
  i0 = 4u;
  i0 = __rust_alloc(i0);
  l4 = i0;
  i0 = !(i0);
  if (i0) {goto B2;}
  i0 = l2;
  i1 = 4u;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l2;
  i1 = 8u;
  i0 += i1;
  l5 = i0;
  i1 = l5;
  i1 = i32_load((&memory), (u64)(i1));
  l5 = i1;
  i2 = 4u;
  i1 += i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = l4;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l4;
  i1 = l5;
  i0 += i1;
  i1 = p1;
  i2 = 2u;
  i1 <<= (i2 & 31);
  i2 = 2u;
  i1 |= i2;
  i32_store((&memory), (u64)(i0), i1);
  goto B11;
  B14:;
  i0 = 1u;
  i0 = __rust_alloc(i0);
  l4 = i0;
  i0 = !(i0);
  if (i0) {goto B1;}
  i0 = l2;
  i1 = 1u;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l2;
  i1 = 8u;
  i0 += i1;
  l5 = i0;
  i1 = l5;
  i1 = i32_load((&memory), (u64)(i1));
  l6 = i1;
  i2 = 1u;
  i1 += i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = l4;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l4;
  i1 = l6;
  i0 += i1;
  i1 = 3u;
  i32_store8((&memory), (u64)(i0), i1);
  i0 = l2;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l6 = i0;
  i1 = l5;
  i1 = i32_load((&memory), (u64)(i1));
  l4 = i1;
  i0 -= i1;
  i1 = 4u;
  i0 = i0 >= i1;
  if (i0) {goto B18;}
  i0 = l4;
  i1 = 4u;
  i0 += i1;
  l5 = i0;
  i1 = l4;
  i0 = i0 < i1;
  if (i0) {goto B9;}
  i0 = l6;
  i1 = 1u;
  i0 <<= (i1 & 31);
  l4 = i0;
  i1 = l5;
  i2 = l5;
  i3 = l4;
  i2 = i2 < i3;
  i0 = i2 ? i0 : i1;
  l4 = i0;
  i1 = 0u;
  i0 = (u32)((s32)i0 < (s32)i1);
  if (i0) {goto B9;}
  i0 = l6;
  i0 = !(i0);
  if (i0) {goto B17;}
  i0 = l2;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = l6;
  i2 = l4;
  i0 = __rust_realloc(i0, i1, i2);
  l5 = i0;
  if (i0) {goto B16;}
  goto B0;
  B18:;
  i0 = l2;
  i0 = i32_load((&memory), (u64)(i0));
  l5 = i0;
  goto B15;
  B17:;
  i0 = l4;
  i0 = __rust_alloc(i0);
  l5 = i0;
  i0 = !(i0);
  if (i0) {goto B0;}
  B16:;
  i0 = l2;
  i1 = l4;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l2;
  i1 = l5;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = 8u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  l4 = i0;
  B15:;
  i0 = l2;
  i1 = 8u;
  i0 += i1;
  i1 = l4;
  i2 = 4u;
  i1 += i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l5;
  i1 = l4;
  i0 += i1;
  i1 = p1;
  i32_store((&memory), (u64)(i0), i1);
  B11:;
  i0 = l3;
  i1 = p1;
  i2 = 5u;
  i1 <<= (i2 & 31);
  i0 += i1;
  l7 = i0;
  i0 = l2;
  i1 = 8u;
  i0 += i1;
  l4 = i0;
  L19: 
    i0 = l2;
    i1 = l3;
    _ZN12parity_codec5codec6Output4push17h9ea53c9a29e96026E(i0, i1);
    i0 = l2;
    i1 = l3;
    i2 = 12u;
    i1 += i2;
    l5 = i1;
    _ZN12parity_codec5codec6Output4push17h9ea53c9a29e96026E(i0, i1);
    i0 = l4;
    i0 = i32_load((&memory), (u64)(i0));
    p1 = i0;
    i0 = l2;
    i0 = i32_load((&memory), (u64)(i0 + 4));
    l6 = i0;
    i0 = l3;
    i1 = 24u;
    i0 += i1;
    i0 = i32_load((&memory), (u64)(i0));
    i1 = 1u;
    i0 = i0 != i1;
    if (i0) {goto B34;}
    i0 = l6;
    i1 = p1;
    i0 = i0 != i1;
    if (i0) {goto B33;}
    i0 = p1;
    i1 = 1u;
    i0 += i1;
    l6 = i0;
    i1 = p1;
    i0 = i0 < i1;
    if (i0) {goto B9;}
    i0 = p1;
    i1 = 1u;
    i0 <<= (i1 & 31);
    l8 = i0;
    i1 = l6;
    i2 = l6;
    i3 = l8;
    i2 = i2 < i3;
    i0 = i2 ? i0 : i1;
    l8 = i0;
    i1 = 0u;
    i0 = (u32)((s32)i0 < (s32)i1);
    if (i0) {goto B9;}
    i0 = p1;
    i0 = !(i0);
    if (i0) {goto B31;}
    i0 = l2;
    i0 = i32_load((&memory), (u64)(i0));
    i1 = p1;
    i2 = l8;
    i0 = __rust_realloc(i0, i1, i2);
    l6 = i0;
    if (i0) {goto B30;}
    goto B8;
    B34:;
    i0 = l6;
    i1 = p1;
    i0 = i0 != i1;
    if (i0) {goto B32;}
    i0 = p1;
    i1 = 1u;
    i0 += i1;
    l6 = i0;
    i1 = p1;
    i0 = i0 < i1;
    if (i0) {goto B9;}
    i0 = p1;
    i1 = 1u;
    i0 <<= (i1 & 31);
    l8 = i0;
    i1 = l6;
    i2 = l6;
    i3 = l8;
    i2 = i2 < i3;
    i0 = i2 ? i0 : i1;
    l8 = i0;
    i1 = 0u;
    i0 = (u32)((s32)i0 < (s32)i1);
    if (i0) {goto B9;}
    i0 = p1;
    i0 = !(i0);
    if (i0) {goto B28;}
    i0 = l2;
    i0 = i32_load((&memory), (u64)(i0));
    i1 = p1;
    i2 = l8;
    i0 = __rust_realloc(i0, i1, i2);
    l6 = i0;
    if (i0) {goto B27;}
    goto B7;
    B33:;
    i0 = l2;
    i0 = i32_load((&memory), (u64)(i0));
    l6 = i0;
    goto B29;
    B32:;
    i0 = l2;
    i0 = i32_load((&memory), (u64)(i0));
    l6 = i0;
    goto B26;
    B31:;
    i0 = l8;
    i0 = __rust_alloc(i0);
    l6 = i0;
    i0 = !(i0);
    if (i0) {goto B8;}
    B30:;
    i0 = l2;
    i1 = l8;
    i32_store((&memory), (u64)(i0 + 4), i1);
    i0 = l2;
    i1 = l6;
    i32_store((&memory), (u64)(i0), i1);
    i0 = l4;
    i0 = i32_load((&memory), (u64)(i0));
    p1 = i0;
    B29:;
    i0 = l4;
    i1 = p1;
    i2 = 1u;
    i1 += i2;
    i32_store((&memory), (u64)(i0), i1);
    i0 = l6;
    i1 = p1;
    i0 += i1;
    i1 = 2u;
    i32_store8((&memory), (u64)(i0), i1);
    i0 = l3;
    i1 = 28u;
    i0 += i1;
    i0 = i32_load((&memory), (u64)(i0));
    l6 = i0;
    i0 = l2;
    i0 = i32_load((&memory), (u64)(i0 + 4));
    l3 = i0;
    i1 = l4;
    i1 = i32_load((&memory), (u64)(i1));
    p1 = i1;
    i0 -= i1;
    i1 = 4u;
    i0 = i0 >= i1;
    if (i0) {goto B35;}
    i0 = p1;
    i1 = 4u;
    i0 += i1;
    l8 = i0;
    i1 = p1;
    i0 = i0 < i1;
    if (i0) {goto B9;}
    i0 = l3;
    i1 = 1u;
    i0 <<= (i1 & 31);
    p1 = i0;
    i1 = l8;
    i2 = l8;
    i3 = p1;
    i2 = i2 < i3;
    i0 = i2 ? i0 : i1;
    p1 = i0;
    i1 = 0u;
    i0 = (u32)((s32)i0 < (s32)i1);
    if (i0) {goto B9;}
    i0 = l3;
    i0 = !(i0);
    if (i0) {goto B25;}
    i0 = l2;
    i0 = i32_load((&memory), (u64)(i0));
    i1 = l3;
    i2 = p1;
    i0 = __rust_realloc(i0, i1, i2);
    l3 = i0;
    if (i0) {goto B24;}
    goto B6;
    B35:;
    i0 = l2;
    i0 = i32_load((&memory), (u64)(i0));
    l3 = i0;
    goto B23;
    B28:;
    i0 = l8;
    i0 = __rust_alloc(i0);
    l6 = i0;
    i0 = !(i0);
    if (i0) {goto B7;}
    B27:;
    i0 = l2;
    i1 = l8;
    i32_store((&memory), (u64)(i0 + 4), i1);
    i0 = l2;
    i1 = l6;
    i32_store((&memory), (u64)(i0), i1);
    i0 = l4;
    i0 = i32_load((&memory), (u64)(i0));
    p1 = i0;
    B26:;
    i0 = l4;
    i1 = p1;
    i2 = 1u;
    i1 += i2;
    i32_store((&memory), (u64)(i0), i1);
    i0 = l6;
    i1 = p1;
    i0 += i1;
    i1 = 1u;
    i32_store8((&memory), (u64)(i0), i1);
    i0 = l3;
    i1 = 28u;
    i0 += i1;
    i0 = i32_load((&memory), (u64)(i0));
    l6 = i0;
    i0 = l2;
    i0 = i32_load((&memory), (u64)(i0 + 4));
    l3 = i0;
    i1 = l4;
    i1 = i32_load((&memory), (u64)(i1));
    p1 = i1;
    i0 -= i1;
    i1 = 4u;
    i0 = i0 >= i1;
    if (i0) {goto B36;}
    i0 = p1;
    i1 = 4u;
    i0 += i1;
    l8 = i0;
    i1 = p1;
    i0 = i0 < i1;
    if (i0) {goto B9;}
    i0 = l3;
    i1 = 1u;
    i0 <<= (i1 & 31);
    p1 = i0;
    i1 = l8;
    i2 = l8;
    i3 = p1;
    i2 = i2 < i3;
    i0 = i2 ? i0 : i1;
    p1 = i0;
    i1 = 0u;
    i0 = (u32)((s32)i0 < (s32)i1);
    if (i0) {goto B9;}
    i0 = l3;
    i0 = !(i0);
    if (i0) {goto B22;}
    i0 = l2;
    i0 = i32_load((&memory), (u64)(i0));
    i1 = l3;
    i2 = p1;
    i0 = __rust_realloc(i0, i1, i2);
    l3 = i0;
    if (i0) {goto B21;}
    goto B5;
    B36:;
    i0 = l2;
    i0 = i32_load((&memory), (u64)(i0));
    l3 = i0;
    goto B20;
    B25:;
    i0 = p1;
    i0 = __rust_alloc(i0);
    l3 = i0;
    i0 = !(i0);
    if (i0) {goto B6;}
    B24:;
    i0 = l2;
    i1 = p1;
    i32_store((&memory), (u64)(i0 + 4), i1);
    i0 = l2;
    i1 = l3;
    i32_store((&memory), (u64)(i0), i1);
    i0 = l4;
    i0 = i32_load((&memory), (u64)(i0));
    p1 = i0;
    B23:;
    i0 = l4;
    i1 = p1;
    i2 = 4u;
    i1 += i2;
    i32_store((&memory), (u64)(i0), i1);
    i0 = l3;
    i1 = p1;
    i0 += i1;
    i1 = l6;
    i32_store((&memory), (u64)(i0), i1);
    i0 = l5;
    i1 = 20u;
    i0 += i1;
    l3 = i0;
    i1 = l7;
    i0 = i0 != i1;
    if (i0) {goto L19;}
    goto B10;
    B22:;
    i0 = p1;
    i0 = __rust_alloc(i0);
    l3 = i0;
    i0 = !(i0);
    if (i0) {goto B5;}
    B21:;
    i0 = l2;
    i1 = p1;
    i32_store((&memory), (u64)(i0 + 4), i1);
    i0 = l2;
    i1 = l3;
    i32_store((&memory), (u64)(i0), i1);
    i0 = l4;
    i0 = i32_load((&memory), (u64)(i0));
    p1 = i0;
    B20:;
    i0 = l4;
    i1 = p1;
    i2 = 4u;
    i1 += i2;
    i32_store((&memory), (u64)(i0), i1);
    i0 = l3;
    i1 = p1;
    i0 += i1;
    i1 = l6;
    i32_store((&memory), (u64)(i0), i1);
    i0 = l5;
    i1 = 20u;
    i0 += i1;
    l3 = i0;
    i1 = l7;
    i0 = i0 != i1;
    if (i0) {goto L19;}
  B10:;
  i0 = p0;
  i1 = l2;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = p0;
  i1 = 8u;
  i0 += i1;
  i1 = l2;
  i2 = 8u;
  i1 += i2;
  i1 = i32_load((&memory), (u64)(i1));
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = 16u;
  i0 += i1;
  g0 = i0;
  goto Bfunc;
  B9:;
  _ZN5alloc7raw_vec17capacity_overflow17h05ed4d24a03bca6bE();
  UNREACHABLE;
  B8:;
  i0 = l8;
  i1 = 1u;
  rust_oom(i0, i1);
  UNREACHABLE;
  B7:;
  i0 = l8;
  i1 = 1u;
  rust_oom(i0, i1);
  UNREACHABLE;
  B6:;
  i0 = p1;
  i1 = 1u;
  rust_oom(i0, i1);
  UNREACHABLE;
  B5:;
  i0 = p1;
  i1 = 1u;
  rust_oom(i0, i1);
  UNREACHABLE;
  B4:;
  i0 = 1u;
  i1 = 1u;
  rust_oom(i0, i1);
  UNREACHABLE;
  B3:;
  i0 = 2u;
  i1 = 1u;
  rust_oom(i0, i1);
  UNREACHABLE;
  B2:;
  i0 = 4u;
  i1 = 1u;
  rust_oom(i0, i1);
  UNREACHABLE;
  B1:;
  i0 = 1u;
  i1 = 1u;
  rust_oom(i0, i1);
  UNREACHABLE;
  B0:;
  i0 = l4;
  i1 = 1u;
  rust_oom(i0, i1);
  UNREACHABLE;
  Bfunc:;
  FUNC_EPILOGUE;
}

static void _ZN20substrate_primitives7sandbox27_IMPL_ENCODE_FOR_TypedValue99__LT_impl_u20_parity_codec__codec__Encode_u20_for_u20_substrate_primitives__sandbox__TypedValue_GT_9encode_to17h055d1be133032210E(u32 p0, u32 p1) {
  u32 l2 = 0, l3 = 0, l4 = 0;
  u64 l5 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  u64 j0, j1;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  l2 = i0;
  i1 = 1u;
  i0 = i0 == i1;
  if (i0) {goto B24;}
  i0 = l2;
  i1 = 2u;
  i0 = i0 == i1;
  if (i0) {goto B25;}
  i0 = l2;
  i1 = 3u;
  i0 = i0 != i1;
  if (i0) {goto B23;}
  i0 = p1;
  i1 = 4u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p1;
  i2 = 8u;
  i1 += i2;
  i1 = i32_load((&memory), (u64)(i1));
  l2 = i1;
  i0 = i0 != i1;
  if (i0) {goto B20;}
  i0 = l2;
  i1 = 1u;
  i0 += i1;
  l3 = i0;
  i1 = l2;
  i0 = i0 < i1;
  if (i0) {goto B2;}
  i0 = l2;
  i1 = 1u;
  i0 <<= (i1 & 31);
  l4 = i0;
  i1 = l3;
  i2 = l3;
  i3 = l4;
  i2 = i2 < i3;
  i0 = i2 ? i0 : i1;
  l4 = i0;
  i1 = 0u;
  i0 = (u32)((s32)i0 < (s32)i1);
  if (i0) {goto B2;}
  i0 = l2;
  i0 = !(i0);
  if (i0) {goto B14;}
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = l2;
  i2 = l4;
  i0 = __rust_realloc(i0, i1, i2);
  l3 = i0;
  i0 = !(i0);
  if (i0) {goto B13;}
  goto B4;
  B25:;
  i0 = p1;
  i1 = 4u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p1;
  i2 = 8u;
  i1 += i2;
  i1 = i32_load((&memory), (u64)(i1));
  l2 = i1;
  i0 = i0 != i1;
  if (i0) {goto B22;}
  i0 = l2;
  i1 = 1u;
  i0 += i1;
  l3 = i0;
  i1 = l2;
  i0 = i0 < i1;
  if (i0) {goto B2;}
  i0 = l2;
  i1 = 1u;
  i0 <<= (i1 & 31);
  l4 = i0;
  i1 = l3;
  i2 = l3;
  i3 = l4;
  i2 = i2 < i3;
  i0 = i2 ? i0 : i1;
  l4 = i0;
  i1 = 0u;
  i0 = (u32)((s32)i0 < (s32)i1);
  if (i0) {goto B2;}
  i0 = l2;
  i0 = !(i0);
  if (i0) {goto B18;}
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = l2;
  i2 = l4;
  i0 = __rust_realloc(i0, i1, i2);
  l3 = i0;
  i0 = !(i0);
  if (i0) {goto B17;}
  goto B6;
  B24:;
  i0 = p1;
  i1 = 4u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p1;
  i2 = 8u;
  i1 += i2;
  i1 = i32_load((&memory), (u64)(i1));
  l2 = i1;
  i0 = i0 != i1;
  if (i0) {goto B21;}
  i0 = l2;
  i1 = 1u;
  i0 += i1;
  l3 = i0;
  i1 = l2;
  i0 = i0 < i1;
  if (i0) {goto B2;}
  i0 = l2;
  i1 = 1u;
  i0 <<= (i1 & 31);
  l4 = i0;
  i1 = l3;
  i2 = l3;
  i3 = l4;
  i2 = i2 < i3;
  i0 = i2 ? i0 : i1;
  l4 = i0;
  i1 = 0u;
  i0 = (u32)((s32)i0 < (s32)i1);
  if (i0) {goto B2;}
  i0 = l2;
  i0 = !(i0);
  if (i0) {goto B16;}
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = l2;
  i2 = l4;
  i0 = __rust_realloc(i0, i1, i2);
  l3 = i0;
  i0 = !(i0);
  if (i0) {goto B15;}
  goto B8;
  B23:;
  i0 = p1;
  i1 = 4u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p1;
  i2 = 8u;
  i1 += i2;
  i1 = i32_load((&memory), (u64)(i1));
  l2 = i1;
  i0 = i0 != i1;
  if (i0) {goto B19;}
  i0 = l2;
  i1 = 1u;
  i0 += i1;
  l3 = i0;
  i1 = l2;
  i0 = i0 < i1;
  if (i0) {goto B2;}
  i0 = l2;
  i1 = 1u;
  i0 <<= (i1 & 31);
  l4 = i0;
  i1 = l3;
  i2 = l3;
  i3 = l4;
  i2 = i2 < i3;
  i0 = i2 ? i0 : i1;
  l4 = i0;
  i1 = 0u;
  i0 = (u32)((s32)i0 < (s32)i1);
  if (i0) {goto B2;}
  i0 = l2;
  i0 = !(i0);
  if (i0) {goto B12;}
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = l2;
  i2 = l4;
  i0 = __rust_realloc(i0, i1, i2);
  l3 = i0;
  i0 = !(i0);
  if (i0) {goto B11;}
  goto B10;
  B22:;
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0));
  l3 = i0;
  goto B5;
  B21:;
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0));
  l3 = i0;
  goto B7;
  B20:;
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0));
  l3 = i0;
  goto B3;
  B19:;
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0));
  l3 = i0;
  goto B9;
  B18:;
  i0 = l4;
  i0 = __rust_alloc(i0);
  l3 = i0;
  if (i0) {goto B6;}
  B17:;
  i0 = l4;
  i1 = 1u;
  rust_oom(i0, i1);
  UNREACHABLE;
  B16:;
  i0 = l4;
  i0 = __rust_alloc(i0);
  l3 = i0;
  if (i0) {goto B8;}
  B15:;
  i0 = l4;
  i1 = 1u;
  rust_oom(i0, i1);
  UNREACHABLE;
  B14:;
  i0 = l4;
  i0 = __rust_alloc(i0);
  l3 = i0;
  if (i0) {goto B4;}
  B13:;
  i0 = l4;
  i1 = 1u;
  rust_oom(i0, i1);
  UNREACHABLE;
  B12:;
  i0 = l4;
  i0 = __rust_alloc(i0);
  l3 = i0;
  if (i0) {goto B10;}
  B11:;
  i0 = l4;
  i1 = 1u;
  rust_oom(i0, i1);
  UNREACHABLE;
  B10:;
  i0 = p1;
  i1 = l3;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p1;
  i1 = 4u;
  i0 += i1;
  i1 = l4;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p1;
  i1 = 8u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  l2 = i0;
  B9:;
  i0 = p1;
  i1 = 8u;
  i0 += i1;
  l4 = i0;
  i1 = l2;
  i2 = 1u;
  i1 += i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l3;
  i1 = l2;
  i0 += i1;
  i1 = 1u;
  i32_store8((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = 4u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  l3 = i0;
  i0 = p1;
  i1 = 4u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  l2 = i0;
  i1 = l4;
  i1 = i32_load((&memory), (u64)(i1));
  p0 = i1;
  i0 -= i1;
  i1 = 4u;
  i0 = i0 >= i1;
  if (i0) {goto B30;}
  i0 = p0;
  i1 = 4u;
  i0 += i1;
  l4 = i0;
  i1 = p0;
  i0 = i0 < i1;
  if (i0) {goto B2;}
  i0 = l2;
  i1 = 1u;
  i0 <<= (i1 & 31);
  p0 = i0;
  i1 = l4;
  i2 = l4;
  i3 = p0;
  i2 = i2 < i3;
  i0 = i2 ? i0 : i1;
  p0 = i0;
  i1 = 0u;
  i0 = (u32)((s32)i0 < (s32)i1);
  if (i0) {goto B2;}
  i0 = l2;
  i0 = !(i0);
  if (i0) {goto B29;}
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = l2;
  i2 = p0;
  i0 = __rust_realloc(i0, i1, i2);
  l2 = i0;
  i0 = !(i0);
  if (i0) {goto B28;}
  goto B27;
  B30:;
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0));
  l2 = i0;
  goto B26;
  B29:;
  i0 = p0;
  i0 = __rust_alloc(i0);
  l2 = i0;
  if (i0) {goto B27;}
  B28:;
  i0 = p0;
  i1 = 1u;
  rust_oom(i0, i1);
  UNREACHABLE;
  B27:;
  i0 = p1;
  i1 = l2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p1;
  i1 = 4u;
  i0 += i1;
  i1 = p0;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p1;
  i1 = 8u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  p0 = i0;
  B26:;
  i0 = p1;
  i1 = 8u;
  i0 += i1;
  i1 = p0;
  i2 = 4u;
  i1 += i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = p0;
  i0 += i1;
  i1 = l3;
  i32_store((&memory), (u64)(i0), i1);
  goto Bfunc;
  B8:;
  i0 = p1;
  i1 = l3;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p1;
  i1 = 4u;
  i0 += i1;
  i1 = l4;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p1;
  i1 = 8u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  l2 = i0;
  B7:;
  i0 = p1;
  i1 = 8u;
  i0 += i1;
  l4 = i0;
  i1 = l2;
  i2 = 1u;
  i1 += i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l3;
  i1 = l2;
  i0 += i1;
  i1 = 2u;
  i32_store8((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = 8u;
  i0 += i1;
  j0 = i64_load((&memory), (u64)(i0));
  l5 = j0;
  i0 = p1;
  i1 = 4u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  l2 = i0;
  i1 = l4;
  i1 = i32_load((&memory), (u64)(i1));
  p0 = i1;
  i0 -= i1;
  i1 = 8u;
  i0 = i0 >= i1;
  if (i0) {goto B35;}
  i0 = p0;
  i1 = 8u;
  i0 += i1;
  l3 = i0;
  i1 = p0;
  i0 = i0 < i1;
  if (i0) {goto B2;}
  i0 = l2;
  i1 = 1u;
  i0 <<= (i1 & 31);
  p0 = i0;
  i1 = l3;
  i2 = l3;
  i3 = p0;
  i2 = i2 < i3;
  i0 = i2 ? i0 : i1;
  p0 = i0;
  i1 = 0u;
  i0 = (u32)((s32)i0 < (s32)i1);
  if (i0) {goto B2;}
  i0 = l2;
  i0 = !(i0);
  if (i0) {goto B34;}
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = l2;
  i2 = p0;
  i0 = __rust_realloc(i0, i1, i2);
  l2 = i0;
  i0 = !(i0);
  if (i0) {goto B33;}
  goto B32;
  B35:;
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0));
  l2 = i0;
  goto B31;
  B34:;
  i0 = p0;
  i0 = __rust_alloc(i0);
  l2 = i0;
  if (i0) {goto B32;}
  B33:;
  i0 = p0;
  i1 = 1u;
  rust_oom(i0, i1);
  UNREACHABLE;
  B32:;
  i0 = p1;
  i1 = l2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p1;
  i1 = 4u;
  i0 += i1;
  i1 = p0;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p1;
  i1 = 8u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  p0 = i0;
  B31:;
  i0 = p1;
  i1 = 8u;
  i0 += i1;
  i1 = p0;
  i2 = 8u;
  i1 += i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = p0;
  i0 += i1;
  j1 = l5;
  i64_store((&memory), (u64)(i0), j1);
  goto Bfunc;
  B6:;
  i0 = p1;
  i1 = l3;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p1;
  i1 = 4u;
  i0 += i1;
  i1 = l4;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p1;
  i1 = 8u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  l2 = i0;
  B5:;
  i0 = p1;
  i1 = 8u;
  i0 += i1;
  l4 = i0;
  i1 = l2;
  i2 = 1u;
  i1 += i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l3;
  i1 = l2;
  i0 += i1;
  i1 = 3u;
  i32_store8((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = 4u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  l3 = i0;
  i0 = p1;
  i1 = 4u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  l2 = i0;
  i1 = l4;
  i1 = i32_load((&memory), (u64)(i1));
  p0 = i1;
  i0 -= i1;
  i1 = 4u;
  i0 = i0 >= i1;
  if (i0) {goto B40;}
  i0 = p0;
  i1 = 4u;
  i0 += i1;
  l4 = i0;
  i1 = p0;
  i0 = i0 < i1;
  if (i0) {goto B2;}
  i0 = l2;
  i1 = 1u;
  i0 <<= (i1 & 31);
  p0 = i0;
  i1 = l4;
  i2 = l4;
  i3 = p0;
  i2 = i2 < i3;
  i0 = i2 ? i0 : i1;
  p0 = i0;
  i1 = 0u;
  i0 = (u32)((s32)i0 < (s32)i1);
  if (i0) {goto B2;}
  i0 = l2;
  i0 = !(i0);
  if (i0) {goto B39;}
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = l2;
  i2 = p0;
  i0 = __rust_realloc(i0, i1, i2);
  l2 = i0;
  i0 = !(i0);
  if (i0) {goto B38;}
  goto B37;
  B40:;
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0));
  l2 = i0;
  goto B36;
  B39:;
  i0 = p0;
  i0 = __rust_alloc(i0);
  l2 = i0;
  if (i0) {goto B37;}
  B38:;
  i0 = p0;
  i1 = 1u;
  rust_oom(i0, i1);
  UNREACHABLE;
  B37:;
  i0 = p1;
  i1 = l2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p1;
  i1 = 4u;
  i0 += i1;
  i1 = p0;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p1;
  i1 = 8u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  p0 = i0;
  B36:;
  i0 = p1;
  i1 = 8u;
  i0 += i1;
  i1 = p0;
  i2 = 4u;
  i1 += i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = p0;
  i0 += i1;
  i1 = l3;
  i32_store((&memory), (u64)(i0), i1);
  goto Bfunc;
  B4:;
  i0 = p1;
  i1 = l3;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p1;
  i1 = 4u;
  i0 += i1;
  i1 = l4;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p1;
  i1 = 8u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  l2 = i0;
  B3:;
  i0 = p1;
  i1 = 8u;
  i0 += i1;
  l4 = i0;
  i1 = l2;
  i2 = 1u;
  i1 += i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l3;
  i1 = l2;
  i0 += i1;
  i1 = 4u;
  i32_store8((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = 8u;
  i0 += i1;
  j0 = i64_load((&memory), (u64)(i0));
  l5 = j0;
  i0 = p1;
  i1 = 4u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  l2 = i0;
  i1 = l4;
  i1 = i32_load((&memory), (u64)(i1));
  p0 = i1;
  i0 -= i1;
  i1 = 8u;
  i0 = i0 >= i1;
  if (i0) {goto B43;}
  i0 = p0;
  i1 = 8u;
  i0 += i1;
  l3 = i0;
  i1 = p0;
  i0 = i0 < i1;
  if (i0) {goto B2;}
  i0 = l2;
  i1 = 1u;
  i0 <<= (i1 & 31);
  p0 = i0;
  i1 = l3;
  i2 = l3;
  i3 = p0;
  i2 = i2 < i3;
  i0 = i2 ? i0 : i1;
  p0 = i0;
  i1 = 0u;
  i0 = (u32)((s32)i0 < (s32)i1);
  if (i0) {goto B2;}
  i0 = l2;
  i0 = !(i0);
  if (i0) {goto B42;}
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = l2;
  i2 = p0;
  i0 = __rust_realloc(i0, i1, i2);
  l2 = i0;
  i0 = !(i0);
  if (i0) {goto B41;}
  goto B1;
  B43:;
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0));
  l2 = i0;
  goto B0;
  B42:;
  i0 = p0;
  i0 = __rust_alloc(i0);
  l2 = i0;
  if (i0) {goto B1;}
  B41:;
  i0 = p0;
  i1 = 1u;
  rust_oom(i0, i1);
  UNREACHABLE;
  B2:;
  _ZN5alloc7raw_vec17capacity_overflow17h05ed4d24a03bca6bE();
  UNREACHABLE;
  B1:;
  i0 = p1;
  i1 = l2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p1;
  i1 = 4u;
  i0 += i1;
  i1 = p0;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p1;
  i1 = 8u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  p0 = i0;
  B0:;
  i0 = p1;
  i1 = 8u;
  i0 += i1;
  i1 = p0;
  i2 = 8u;
  i1 += i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = p0;
  i0 += i1;
  j1 = l5;
  i64_store((&memory), (u64)(i0), j1);
  Bfunc:;
  FUNC_EPILOGUE;
}

static void _ZN12parity_codec5codec6Encode6encode17ha70755ab770d169bE(u32 p0, u32 p1) {
  u32 l2 = 0, l3 = 0, l4 = 0, l5 = 0, l6 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  u64 j1;
  i0 = g0;
  i1 = 16u;
  i0 -= i1;
  l2 = i0;
  g0 = i0;
  i0 = l2;
  i1 = 0u;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = l2;
  j1 = 1ull;
  i64_store((&memory), (u64)(i0), j1);
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0));
  l3 = i0;
  i0 = 1u;
  i0 = __rust_alloc(i0);
  l4 = i0;
  i0 = l3;
  i1 = 5u;
  i0 = i0 != i1;
  if (i0) {goto B8;}
  i0 = l4;
  i0 = !(i0);
  if (i0) {goto B7;}
  i0 = l2;
  i1 = 8u;
  i0 += i1;
  l3 = i0;
  i1 = l3;
  i1 = i32_load((&memory), (u64)(i1));
  l3 = i1;
  i2 = 1u;
  i1 += i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = 1u;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l2;
  i1 = l4;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l4;
  i1 = l3;
  i0 += i1;
  i1 = 1u;
  i32_store8((&memory), (u64)(i0), i1);
  goto B0;
  B8:;
  i0 = l4;
  i0 = !(i0);
  if (i0) {goto B6;}
  i0 = l2;
  i1 = 1u;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l2;
  i1 = 8u;
  i0 += i1;
  l5 = i0;
  i1 = l5;
  i1 = i32_load((&memory), (u64)(i1));
  l6 = i1;
  i2 = 1u;
  i1 += i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = l4;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l4;
  i1 = l6;
  i0 += i1;
  i1 = 0u;
  i32_store8((&memory), (u64)(i0), i1);
  i0 = l5;
  i0 = i32_load((&memory), (u64)(i0));
  l4 = i0;
  i0 = l2;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  l5 = i0;
  i0 = l3;
  i1 = 4u;
  i0 = i0 != i1;
  if (i0) {goto B15;}
  i0 = l5;
  i1 = l4;
  i0 = i0 != i1;
  if (i0) {goto B14;}
  i0 = l4;
  i1 = 1u;
  i0 += i1;
  l3 = i0;
  i1 = l4;
  i0 = i0 < i1;
  if (i0) {goto B5;}
  i0 = l4;
  i1 = 1u;
  i0 <<= (i1 & 31);
  p1 = i0;
  i1 = l3;
  i2 = l3;
  i3 = p1;
  i2 = i2 < i3;
  i0 = i2 ? i0 : i1;
  p1 = i0;
  i1 = 0u;
  i0 = (u32)((s32)i0 < (s32)i1);
  if (i0) {goto B5;}
  i0 = l4;
  i0 = !(i0);
  if (i0) {goto B12;}
  i0 = l2;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = l4;
  i2 = p1;
  i0 = __rust_realloc(i0, i1, i2);
  l3 = i0;
  i0 = !(i0);
  if (i0) {goto B11;}
  goto B2;
  B15:;
  i0 = l5;
  i1 = l4;
  i0 = i0 != i1;
  if (i0) {goto B13;}
  i0 = l4;
  i1 = 1u;
  i0 += i1;
  l3 = i0;
  i1 = l4;
  i0 = i0 < i1;
  if (i0) {goto B5;}
  i0 = l4;
  i1 = 1u;
  i0 <<= (i1 & 31);
  l5 = i0;
  i1 = l3;
  i2 = l3;
  i3 = l5;
  i2 = i2 < i3;
  i0 = i2 ? i0 : i1;
  l5 = i0;
  i1 = 0u;
  i0 = (u32)((s32)i0 < (s32)i1);
  if (i0) {goto B5;}
  i0 = l4;
  i0 = !(i0);
  if (i0) {goto B10;}
  i0 = l2;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = l4;
  i2 = l5;
  i0 = __rust_realloc(i0, i1, i2);
  l3 = i0;
  i0 = !(i0);
  if (i0) {goto B9;}
  goto B4;
  B14:;
  i0 = l2;
  i0 = i32_load((&memory), (u64)(i0));
  l3 = i0;
  goto B1;
  B13:;
  i0 = l2;
  i0 = i32_load((&memory), (u64)(i0));
  l3 = i0;
  goto B3;
  B12:;
  i0 = p1;
  i0 = __rust_alloc(i0);
  l3 = i0;
  if (i0) {goto B2;}
  B11:;
  i0 = p1;
  i1 = 1u;
  rust_oom(i0, i1);
  UNREACHABLE;
  B10:;
  i0 = l5;
  i0 = __rust_alloc(i0);
  l3 = i0;
  if (i0) {goto B4;}
  B9:;
  i0 = l5;
  i1 = 1u;
  rust_oom(i0, i1);
  UNREACHABLE;
  B7:;
  i0 = 1u;
  i1 = 1u;
  rust_oom(i0, i1);
  UNREACHABLE;
  B6:;
  i0 = 1u;
  i1 = 1u;
  rust_oom(i0, i1);
  UNREACHABLE;
  B5:;
  _ZN5alloc7raw_vec17capacity_overflow17h05ed4d24a03bca6bE();
  UNREACHABLE;
  B4:;
  i0 = l2;
  i1 = l5;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l2;
  i1 = l3;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = 8u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  l4 = i0;
  B3:;
  i0 = l2;
  i1 = 8u;
  i0 += i1;
  i1 = l4;
  i2 = 1u;
  i1 += i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l3;
  i1 = l4;
  i0 += i1;
  i1 = 1u;
  i32_store8((&memory), (u64)(i0), i1);
  i0 = p1;
  i1 = l2;
  _ZN20substrate_primitives7sandbox27_IMPL_ENCODE_FOR_TypedValue99__LT_impl_u20_parity_codec__codec__Encode_u20_for_u20_substrate_primitives__sandbox__TypedValue_GT_9encode_to17h055d1be133032210E(i0, i1);
  goto B0;
  B2:;
  i0 = l2;
  i1 = p1;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l2;
  i1 = l3;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = 8u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  l4 = i0;
  B1:;
  i0 = l2;
  i1 = 8u;
  i0 += i1;
  i1 = l4;
  i2 = 1u;
  i1 += i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l3;
  i1 = l4;
  i0 += i1;
  i1 = 0u;
  i32_store8((&memory), (u64)(i0), i1);
  B0:;
  i0 = p0;
  i1 = l2;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = p0;
  i1 = 8u;
  i0 += i1;
  i1 = l2;
  i2 = 8u;
  i1 += i2;
  i1 = i32_load((&memory), (u64)(i1));
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = 16u;
  i0 += i1;
  g0 = i0;
  FUNC_EPILOGUE;
}

u64 test_data_in(u32 p0, u32 p1) {
  fprintf(stderr, "test_data_in, p0 %d\n", p0);
  fprintf(stderr, "test_data_in, p1 %d\n", p1);
  u32 l2 = 0, l3 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4;
  u64 j0, j1;
  i0 = g0;
  i1 = 16u;
  i0 -= i1;
  l2 = i0;
  g0 = i0;
  i0 = 1048949u;
  i1 = 11u;
  fprintf(stderr, "before print\n");

  Z_envZ_ext_print_utf8Z_vii(i0, i1);

  //(*Z_envZ_ext_print_utf8Z_vii)(i0, i1);
  fprintf(stderr, "after print\n");
  i0 = 1048960u;
  i1 = 5u;
  i2 = p0;
  i3 = 1049368u;
  i4 = p1;
  i2 = i4 ? i2 : i3;
  i3 = p1;
  fprintf(stderr, "1\n");
  Z_envZ_ext_set_storageZ_viiii(i0, i1, i2, i3);
  i0 = 1048965u;
  i1 = 7u;
  Z_envZ_ext_print_utf8Z_vii(i0, i1);
  i0 = l2;
  i1 = 0u;
  fprintf(stderr, "2\n");
  i32_store((&memory), (u64)(i0 + 12), i1);
  fprintf(stderr, "2.5\n");
  i0 = 1048972u;
  i1 = 3u;
  i2 = l2;
  i3 = 12u;
  i2 += i3;
  fprintf(stderr, "3\n");
  i0 = Z_envZ_ext_get_allocated_storageZ_iiii(i0, i1, i2);
  l3 = i0;
  i0 = l2;
  fprintf(stderr, "4\n");
  i0 = i32_load((&memory), (u64)(i0 + 12));
  p0 = i0;
  i1 = 4294967295u;
  i0 = i0 == i1;
  if (i0) {goto B1;}
  i0 = 1048949u;
  i1 = 11u;
  Z_envZ_ext_print_utf8Z_vii(i0, i1);
  i0 = 1048975u;
  i1 = 3u;
  i2 = l3;
  i3 = p0;
  fprintf(stderr, "5\n");
  Z_envZ_ext_set_storageZ_viiii(i0, i1, i2, i3);
  fprintf(stderr, "5.5\n");
  i0 = 1048978u;
  i1 = 9u;
  Z_envZ_ext_print_utf8Z_vii(i0, i1);
  i0 = 7u;
  fprintf(stderr, "5.8\n");
  fprintf(stderr, "5.8 %d\n", i0);
  i0 = __rust_alloc(i0);
  fprintf(stderr, "5.9\n");
  p1 = i0;
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = p1;
  i1 = 6u;
  i0 += i1;
  i1 = 0u;
  fprintf(stderr, "6\n");
  i1 = i32_load8_u((&memory), (u64)(i1 + 1048993));
  i32_store8((&memory), (u64)(i0), i1);
  i0 = p1;
  i1 = 4u;
  i0 += i1;
  i1 = 0u;
  i1 = i32_load16_u((&memory), (u64)(i1 + 1048991));
  i32_store16((&memory), (u64)(i0), i1);
  i0 = p1;
  i1 = 0u;
  i1 = i32_load((&memory), (u64)(i1 + 1048987));
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i0 = !(i0);
  if (i0) {goto B2;}
  i0 = l3;
  fprintf(stderr, "7\n");
  __rust_dealloc(i0);
  B2:;
  i0 = l2;
  i1 = 16u;
  i0 += i1;
  g0 = i0;
  i0 = p1;
  j0 = (u64)(i0);
  j1 = 30064771072ull;
  j0 |= j1;
  goto Bfunc;
  B1:;
  i0 = 1049716u;
  _ZN4core9panicking5panic17hc8c3dd99127c917dE(i0);
  UNREACHABLE;
  B0:;
  i0 = 7u;
  i1 = 1u;
  rust_oom(i0, i1);
  UNREACHABLE;
  Bfunc:;
  FUNC_EPILOGUE;
  fprintf(stderr, "end!");
  return j0;
}

static u64 test_clear_prefix(u32 p0, u32 p1) {
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  u64 j0, j1;
  i0 = p0;
  i1 = 1049368u;
  i2 = p1;
  i0 = i2 ? i0 : i1;
  i1 = p1;
  (*Z_envZ_ext_clear_prefixZ_vii)(i0, i1);
  i0 = 7u;
  i0 = __rust_alloc(i0);
  p1 = i0;
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = p1;
  i1 = 6u;
  i0 += i1;
  i1 = 0u;
  i1 = i32_load8_u((&memory), (u64)(i1 + 1048993));
  i32_store8((&memory), (u64)(i0), i1);
  i0 = p1;
  i1 = 4u;
  i0 += i1;
  i1 = 0u;
  i1 = i32_load16_u((&memory), (u64)(i1 + 1048991));
  i32_store16((&memory), (u64)(i0), i1);
  i0 = p1;
  i1 = 0u;
  i1 = i32_load((&memory), (u64)(i1 + 1048987));
  i32_store((&memory), (u64)(i0), i1);
  i0 = p1;
  j0 = (u64)(i0);
  j1 = 30064771072ull;
  j0 |= j1;
  goto Bfunc;
  B0:;
  i0 = 7u;
  i1 = 1u;
  rust_oom(i0, i1);
  UNREACHABLE;
  Bfunc:;
  FUNC_EPILOGUE;
  return j0;
}

u64 bar(u32 p0, u32 p1) {
  fprintf(stderr, "bar");
    return 1;
}

u64 test_empty_return(u32 p0, u32 p1) {
  //fprintf(stderr, "test_empty_return, before epilogue");
  //fprintf(stderr, "test_empty_return(%d, %d)\n", p0, p1);
  FUNC_PROLOGUE;
  u64 j0;
  j0 = 1ull;
  FUNC_EPILOGUE;
  fprintf(stderr, "test_empty_return, after epilogue\n");
  fprintf(stderr, "test_empty_return, return with %d\n", j0);
  return &j0;
  //return 1;
}

static u64 test_panic(u32 p0, u32 p1) {
  FUNC_PROLOGUE;
  u64 j0;
  _ZN12runtime_test10test_panic28__u7b__u7b_closure_u7d__u7d_17hac0217cdb3c42e04E();
  UNREACHABLE;
  FUNC_EPILOGUE;
  return j0;
}

static void _ZN12runtime_test10test_panic28__u7b__u7b_closure_u7d__u7d_17hac0217cdb3c42e04E(void) {
  FUNC_PROLOGUE;
  u32 i0;
  i0 = 1049740u;
  _ZN4core9panicking5panic17hc8c3dd99127c917dE(i0);
  UNREACHABLE;
  FUNC_EPILOGUE;
}

static u64 test_conditional_panic(u32 p0, u32 p1) {
  FUNC_PROLOGUE;
  u32 i0;
  u64 j0;
  i0 = p1;
  if (i0) {goto B0;}
  j0 = 1ull;
  goto Bfunc;
  B0:;
  i0 = 1049764u;
  _ZN4core9panicking5panic17hc8c3dd99127c917dE(i0);
  UNREACHABLE;
  Bfunc:;
  FUNC_EPILOGUE;
  return j0;
}

static u64 test_blake2_256(u32 p0, u32 p1) {
  u32 l2 = 0, l3 = 0, l4 = 0, l5 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  u64 j0, j1;
  i0 = g0;
  i1 = 64u;
  i0 -= i1;
  l2 = i0;
  g0 = i0;
  i0 = l2;
  i1 = 32u;
  i0 += i1;
  i1 = 24u;
  i0 += i1;
  l3 = i0;
  j1 = 0ull;
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  i1 = 32u;
  i0 += i1;
  i1 = 16u;
  i0 += i1;
  l4 = i0;
  j1 = 0ull;
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  i1 = 32u;
  i0 += i1;
  i1 = 8u;
  i0 += i1;
  l5 = i0;
  j1 = 0ull;
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  j1 = 0ull;
  i64_store((&memory), (u64)(i0 + 32), j1);
  i0 = p0;
  i1 = 1049368u;
  i2 = p1;
  i0 = i2 ? i0 : i1;
  i1 = p1;
  i2 = l2;
  i3 = 32u;
  i2 += i3;
  (*Z_envZ_ext_blake2_256Z_viii)(i0, i1, i2);
  i0 = l2;
  i1 = 24u;
  i0 += i1;
  p0 = i0;
  i1 = l3;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  i1 = 16u;
  i0 += i1;
  l3 = i0;
  i1 = l4;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  i1 = 8u;
  i0 += i1;
  l4 = i0;
  i1 = l5;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  i1 = l2;
  j1 = i64_load((&memory), (u64)(i1 + 32));
  i64_store((&memory), (u64)(i0), j1);
  i0 = 32u;
  i0 = __rust_alloc(i0);
  p1 = i0;
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = p1;
  i1 = l2;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = p1;
  i1 = 24u;
  i0 += i1;
  i1 = p0;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = p1;
  i1 = 16u;
  i0 += i1;
  i1 = l3;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = p1;
  i1 = 8u;
  i0 += i1;
  i1 = l4;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  i1 = 64u;
  i0 += i1;
  g0 = i0;
  i0 = p1;
  j0 = (u64)(i0);
  j1 = 137438953472ull;
  j0 |= j1;
  goto Bfunc;
  B0:;
  i0 = 32u;
  i1 = 1u;
  rust_oom(i0, i1);
  UNREACHABLE;
  Bfunc:;
  FUNC_EPILOGUE;
  return j0;
}

static u64 test_twox_256(u32 p0, u32 p1) {
  u32 l2 = 0, l3 = 0, l4 = 0, l5 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  u64 j0, j1;
  i0 = g0;
  i1 = 64u;
  i0 -= i1;
  l2 = i0;
  g0 = i0;
  i0 = l2;
  i1 = 32u;
  i0 += i1;
  i1 = 24u;
  i0 += i1;
  l3 = i0;
  j1 = 0ull;
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  i1 = 32u;
  i0 += i1;
  i1 = 16u;
  i0 += i1;
  l4 = i0;
  j1 = 0ull;
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  i1 = 32u;
  i0 += i1;
  i1 = 8u;
  i0 += i1;
  l5 = i0;
  j1 = 0ull;
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  j1 = 0ull;
  i64_store((&memory), (u64)(i0 + 32), j1);
  i0 = p0;
  i1 = 1049368u;
  i2 = p1;
  i0 = i2 ? i0 : i1;
  i1 = p1;
  i2 = l2;
  i3 = 32u;
  i2 += i3;
  (*Z_envZ_ext_twox_256Z_viii)(i0, i1, i2);
  i0 = l2;
  i1 = 24u;
  i0 += i1;
  p0 = i0;
  i1 = l3;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  i1 = 16u;
  i0 += i1;
  l3 = i0;
  i1 = l4;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  i1 = 8u;
  i0 += i1;
  l4 = i0;
  i1 = l5;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  i1 = l2;
  j1 = i64_load((&memory), (u64)(i1 + 32));
  i64_store((&memory), (u64)(i0), j1);
  i0 = 32u;
  i0 = __rust_alloc(i0);
  p1 = i0;
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = p1;
  i1 = l2;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = p1;
  i1 = 24u;
  i0 += i1;
  i1 = p0;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = p1;
  i1 = 16u;
  i0 += i1;
  i1 = l3;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = p1;
  i1 = 8u;
  i0 += i1;
  i1 = l4;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  i1 = 64u;
  i0 += i1;
  g0 = i0;
  i0 = p1;
  j0 = (u64)(i0);
  j1 = 137438953472ull;
  j0 |= j1;
  goto Bfunc;
  B0:;
  i0 = 32u;
  i1 = 1u;
  rust_oom(i0, i1);
  UNREACHABLE;
  Bfunc:;
  FUNC_EPILOGUE;
  return j0;
}

static u64 test_twox_128(u32 p0, u32 p1) {
  u32 l2 = 0, l3 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  u64 j0, j1;
  i0 = g0;
  i1 = 32u;
  i0 -= i1;
  l2 = i0;
  g0 = i0;
  i0 = l2;
  i1 = 16u;
  i0 += i1;
  i1 = 8u;
  i0 += i1;
  l3 = i0;
  j1 = 0ull;
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  j1 = 0ull;
  i64_store((&memory), (u64)(i0 + 16), j1);
  i0 = p0;
  i1 = 1049368u;
  i2 = p1;
  i0 = i2 ? i0 : i1;
  i1 = p1;
  i2 = l2;
  i3 = 16u;
  i2 += i3;
  (*Z_envZ_ext_twox_128Z_viii)(i0, i1, i2);
  i0 = l2;
  i1 = 8u;
  i0 += i1;
  p0 = i0;
  i1 = l3;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  i1 = l2;
  j1 = i64_load((&memory), (u64)(i1 + 16));
  i64_store((&memory), (u64)(i0), j1);
  i0 = 16u;
  i0 = __rust_alloc(i0);
  p1 = i0;
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = p1;
  i1 = l2;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = p1;
  i1 = 8u;
  i0 += i1;
  i1 = p0;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  i1 = 32u;
  i0 += i1;
  g0 = i0;
  i0 = p1;
  j0 = (u64)(i0);
  j1 = 68719476736ull;
  j0 |= j1;
  goto Bfunc;
  B0:;
  i0 = 16u;
  i1 = 1u;
  rust_oom(i0, i1);
  UNREACHABLE;
  Bfunc:;
  FUNC_EPILOGUE;
  return j0;
}

static u64 test_ed25519_verify(u32 p0, u32 p1) {
  u32 l2 = 0, l3 = 0, l4 = 0, l5 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  u64 j0, j1;
  i0 = g0;
  i1 = 96u;
  i0 -= i1;
  l2 = i0;
  g0 = i0;
  i0 = l2;
  i1 = 24u;
  i0 += i1;
  l3 = i0;
  j1 = 0ull;
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  i1 = 16u;
  i0 += i1;
  l4 = i0;
  j1 = 0ull;
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  i1 = 8u;
  i0 += i1;
  l5 = i0;
  j1 = 0ull;
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  j1 = 0ull;
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  i1 = 88u;
  i0 += i1;
  j1 = 0ull;
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  i1 = 80u;
  i0 += i1;
  j1 = 0ull;
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  i1 = 72u;
  i0 += i1;
  j1 = 0ull;
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  i1 = 32u;
  i0 += i1;
  i1 = 32u;
  i0 += i1;
  j1 = 0ull;
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  i1 = 32u;
  i0 += i1;
  i1 = 24u;
  i0 += i1;
  j1 = 0ull;
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  i1 = 32u;
  i0 += i1;
  i1 = 16u;
  i0 += i1;
  j1 = 0ull;
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  i1 = 32u;
  i0 += i1;
  i1 = 8u;
  i0 += i1;
  j1 = 0ull;
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  j1 = 0ull;
  i64_store((&memory), (u64)(i0 + 32), j1);
  i0 = p1;
  i1 = 31u;
  i0 = i0 <= i1;
  if (i0) {goto B2;}
  i0 = l3;
  i1 = p0;
  i2 = 1049368u;
  i3 = p1;
  i1 = i3 ? i1 : i2;
  p0 = i1;
  i2 = 24u;
  i1 += i2;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l4;
  i1 = p0;
  i2 = 16u;
  i1 += i2;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l5;
  i1 = p0;
  i2 = 8u;
  i1 += i2;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  i1 = p0;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = p1;
  i1 = 95u;
  i0 = i0 <= i1;
  if (i0) {goto B1;}
  i0 = l2;
  i1 = 32u;
  i0 += i1;
  i1 = 56u;
  i0 += i1;
  i1 = p0;
  i2 = 88u;
  i1 += i2;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  i1 = 32u;
  i0 += i1;
  i1 = 48u;
  i0 += i1;
  i1 = p0;
  i2 = 80u;
  i1 += i2;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  i1 = 32u;
  i0 += i1;
  i1 = 40u;
  i0 += i1;
  i1 = p0;
  i2 = 72u;
  i1 += i2;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  i1 = 64u;
  i0 += i1;
  i1 = p0;
  i2 = 64u;
  i1 += i2;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  i1 = 56u;
  i0 += i1;
  i1 = p0;
  i2 = 56u;
  i1 += i2;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  i1 = 48u;
  i0 += i1;
  i1 = p0;
  i2 = 48u;
  i1 += i2;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  i1 = 40u;
  i0 += i1;
  i1 = p0;
  i2 = 40u;
  i1 += i2;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  i1 = p0;
  j1 = i64_load((&memory), (u64)(i1 + 32));
  i64_store((&memory), (u64)(i0 + 32), j1);
  i0 = 1048987u;
  i1 = 7u;
  i2 = l2;
  i3 = 32u;
  i2 += i3;
  i3 = l2;
  i0 = (*Z_envZ_ext_ed25519_verifyZ_iiiii)(i0, i1, i2, i3);
  p1 = i0;
  i0 = 1u;
  i0 = __rust_alloc(i0);
  p0 = i0;
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = p0;
  i1 = p1;
  i1 = !(i1);
  i32_store8((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = 96u;
  i0 += i1;
  g0 = i0;
  i0 = p0;
  j0 = (u64)(i0);
  j1 = 4294967296ull;
  j0 |= j1;
  goto Bfunc;
  B2:;
  i0 = 32u;
  i1 = p1;
  _ZN4core5slice20slice_index_len_fail17h4903095f5ffa1112E(i0, i1);
  UNREACHABLE;
  B1:;
  i0 = 96u;
  i1 = p1;
  _ZN4core5slice20slice_index_len_fail17h4903095f5ffa1112E(i0, i1);
  UNREACHABLE;
  B0:;
  i0 = 1u;
  i1 = 1u;
  rust_oom(i0, i1);
  UNREACHABLE;
  Bfunc:;
  FUNC_EPILOGUE;
  return j0;
}

static u64 test_enumerated_trie_root(u32 p0, u32 p1) {
  u32 l2 = 0, l3 = 0, l4 = 0, l5 = 0, l6 = 0, l7 = 0, l8 = 0, l9 = 0, 
      l10 = 0, l11 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4;
  u64 j0, j1;
  i0 = g0;
  i1 = 96u;
  i0 -= i1;
  l2 = i0;
  g0 = i0;
  i0 = l2;
  i1 = 60u;
  i0 += i1;
  l3 = i0;
  i1 = 3u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = 40u;
  i0 += i1;
  i1 = 12u;
  i0 += i1;
  l4 = i0;
  i1 = 3u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = 1049085u;
  i32_store((&memory), (u64)(i0 + 56), i1);
  i0 = l2;
  i1 = 1049082u;
  i32_store((&memory), (u64)(i0 + 48), i1);
  i0 = l2;
  i1 = 4u;
  i32_store((&memory), (u64)(i0 + 44), i1);
  i0 = l2;
  i1 = 1049078u;
  i32_store((&memory), (u64)(i0 + 40), i1);
  i0 = 12u;
  i0 = __rust_alloc(i0);
  l5 = i0;
  i0 = !(i0);
  if (i0) {goto B1;}
  i0 = l5;
  i1 = l2;
  i1 = i32_load((&memory), (u64)(i1 + 44));
  l6 = i1;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l5;
  i1 = l4;
  i1 = i32_load((&memory), (u64)(i1));
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l5;
  i1 = l3;
  i1 = i32_load((&memory), (u64)(i1));
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = l2;
  i0 = i32_load((&memory), (u64)(i0 + 40));
  l4 = i0;
  i0 = l6;
  i0 = !(i0);
  if (i0) {goto B5;}
  i0 = l6;
  i1 = 0u;
  i0 = (u32)((s32)i0 < (s32)i1);
  if (i0) {goto B3;}
  i0 = l6;
  l7 = i0;
  i0 = l6;
  i0 = __rust_alloc(i0);
  l3 = i0;
  if (i0) {goto B4;}
  i0 = l6;
  l8 = i0;
  goto B2;
  B5:;
  i0 = 0u;
  l7 = i0;
  i0 = 1u;
  l3 = i0;
  B4:;
  i0 = l3;
  i1 = l4;
  i2 = l6;
  i0 = memcpy_0(i0, i1, i2);
  l9 = i0;
  i0 = l2;
  i0 = i32_load((&memory), (u64)(i0 + 48));
  l10 = i0;
  i0 = l7;
  i1 = l6;
  i0 -= i1;
  i1 = l2;
  i2 = 52u;
  i1 += i2;
  i1 = i32_load((&memory), (u64)(i1));
  l11 = i1;
  i0 = i0 >= i1;
  if (i0) {goto B8;}
  i0 = l6;
  i1 = l11;
  i0 += i1;
  l4 = i0;
  i1 = l6;
  i0 = i0 < i1;
  if (i0) {goto B3;}
  i0 = l7;
  i1 = 1u;
  i0 <<= (i1 & 31);
  l3 = i0;
  i1 = l4;
  i2 = l4;
  i3 = l3;
  i2 = i2 < i3;
  i0 = i2 ? i0 : i1;
  l8 = i0;
  i1 = 0u;
  i0 = (u32)((s32)i0 < (s32)i1);
  if (i0) {goto B3;}
  i0 = l7;
  i0 = !(i0);
  if (i0) {goto B7;}
  i0 = l9;
  i1 = l7;
  i2 = l8;
  i0 = __rust_realloc(i0, i1, i2);
  l3 = i0;
  if (i0) {goto B6;}
  goto B2;
  B8:;
  i0 = l11;
  i1 = l6;
  i0 += i1;
  l4 = i0;
  i0 = l7;
  l8 = i0;
  goto B6;
  B7:;
  i0 = l8;
  i0 = __rust_alloc(i0);
  l3 = i0;
  i0 = !(i0);
  if (i0) {goto B2;}
  B6:;
  i0 = l3;
  i1 = l6;
  i0 += i1;
  i1 = l10;
  i2 = l11;
  i0 = memcpy_0(i0, i1, i2);
  i0 = l2;
  i0 = i32_load((&memory), (u64)(i0 + 56));
  l11 = i0;
  i0 = l8;
  i1 = l4;
  i0 -= i1;
  i1 = l2;
  i2 = 60u;
  i1 += i2;
  i1 = i32_load((&memory), (u64)(i1));
  l7 = i1;
  i0 = i0 >= i1;
  if (i0) {goto B11;}
  i0 = l4;
  i1 = l7;
  i0 += i1;
  l6 = i0;
  i1 = l4;
  i0 = i0 < i1;
  if (i0) {goto B3;}
  i0 = l8;
  i1 = 1u;
  i0 <<= (i1 & 31);
  l10 = i0;
  i1 = l6;
  i2 = l6;
  i3 = l10;
  i2 = i2 < i3;
  i0 = i2 ? i0 : i1;
  l6 = i0;
  i1 = 0u;
  i0 = (u32)((s32)i0 < (s32)i1);
  if (i0) {goto B3;}
  i0 = l8;
  i0 = !(i0);
  if (i0) {goto B10;}
  i0 = l3;
  i1 = l8;
  i2 = l6;
  i0 = __rust_realloc(i0, i1, i2);
  l3 = i0;
  i0 = l6;
  l8 = i0;
  i0 = l3;
  if (i0) {goto B9;}
  goto B2;
  B11:;
  i0 = l8;
  l6 = i0;
  goto B9;
  B10:;
  i0 = l6;
  l8 = i0;
  i0 = l6;
  i0 = __rust_alloc(i0);
  l3 = i0;
  i0 = !(i0);
  if (i0) {goto B2;}
  B9:;
  i0 = l3;
  i1 = l4;
  i0 += i1;
  i1 = l11;
  i2 = l7;
  i0 = memcpy_0(i0, i1, i2);
  i0 = l2;
  i1 = 64u;
  i0 += i1;
  i1 = 24u;
  i0 += i1;
  l4 = i0;
  j1 = 0ull;
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  i1 = 64u;
  i0 += i1;
  i1 = 16u;
  i0 += i1;
  l8 = i0;
  j1 = 0ull;
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  i1 = 64u;
  i0 += i1;
  i1 = 8u;
  i0 += i1;
  l7 = i0;
  j1 = 0ull;
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  j1 = 0ull;
  i64_store((&memory), (u64)(i0 + 64), j1);
  i0 = l3;
  i1 = l5;
  i2 = 3u;
  i3 = l2;
  i4 = 64u;
  i3 += i4;
  (*Z_envZ_ext_blake2_256_enumerated_trie_rootZ_viiii)(i0, i1, i2, i3);
  i0 = l2;
  i1 = 8u;
  i0 += i1;
  i1 = 24u;
  i0 += i1;
  i1 = l4;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  i1 = 8u;
  i0 += i1;
  i1 = 16u;
  i0 += i1;
  i1 = l8;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  i1 = 8u;
  i0 += i1;
  i1 = 8u;
  i0 += i1;
  i1 = l7;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  i1 = l2;
  j1 = i64_load((&memory), (u64)(i1 + 64));
  i64_store((&memory), (u64)(i0 + 8), j1);
  i0 = l6;
  i0 = !(i0);
  if (i0) {goto B12;}
  i0 = l3;
  __rust_dealloc(i0);
  B12:;
  i0 = l5;
  __rust_dealloc(i0);
  i0 = 32u;
  i0 = __rust_alloc(i0);
  l6 = i0;
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = l6;
  i1 = l2;
  j1 = i64_load((&memory), (u64)(i1 + 8));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l6;
  i1 = 24u;
  i0 += i1;
  i1 = l2;
  i2 = 8u;
  i1 += i2;
  i2 = 24u;
  i1 += i2;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l6;
  i1 = 16u;
  i0 += i1;
  i1 = l2;
  i2 = 8u;
  i1 += i2;
  i2 = 16u;
  i1 += i2;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l6;
  i1 = 8u;
  i0 += i1;
  i1 = l2;
  i2 = 8u;
  i1 += i2;
  i2 = 8u;
  i1 += i2;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  i1 = 96u;
  i0 += i1;
  g0 = i0;
  i0 = l6;
  j0 = (u64)(i0);
  j1 = 137438953472ull;
  j0 |= j1;
  goto Bfunc;
  B3:;
  _ZN5alloc7raw_vec17capacity_overflow17h05ed4d24a03bca6bE();
  UNREACHABLE;
  B2:;
  i0 = l8;
  i1 = 1u;
  rust_oom(i0, i1);
  UNREACHABLE;
  B1:;
  i0 = 12u;
  i1 = 4u;
  rust_oom(i0, i1);
  UNREACHABLE;
  B0:;
  i0 = 32u;
  i1 = 1u;
  rust_oom(i0, i1);
  UNREACHABLE;
  Bfunc:;
  FUNC_EPILOGUE;
  return j0;
}

static u64 test_sandbox(u32 p0, u32 p1) {
  u32 l2 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4;
  u64 j0, j1;
  i0 = g0;
  i1 = 16u;
  i0 -= i1;
  l2 = i0;
  g0 = i0;
  i0 = l2;
  i1 = p0;
  i2 = 1049368u;
  i3 = p1;
  i1 = i3 ? i1 : i2;
  i2 = p1;
  i3 = 1049368u;
  i4 = 0u;
  _ZN12runtime_test17execute_sandboxed17h7fa747205b7314a3E(i0, i1, i2, i3, i4);
  i0 = l2;
  i0 = i32_load((&memory), (u64)(i0));
  p0 = i0;
  i0 = 1u;
  i0 = __rust_alloc(i0);
  p1 = i0;
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = p1;
  i1 = p0;
  i2 = 5u;
  i1 = i1 != i2;
  i32_store8((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = 16u;
  i0 += i1;
  g0 = i0;
  i0 = p1;
  j0 = (u64)(i0);
  j1 = 4294967296ull;
  j0 |= j1;
  goto Bfunc;
  B0:;
  i0 = 1u;
  i1 = 1u;
  rust_oom(i0, i1);
  UNREACHABLE;
  Bfunc:;
  FUNC_EPILOGUE;
  return j0;
}

static void _ZN12runtime_test17execute_sandboxed17h7fa747205b7314a3E(u32 p0, u32 p1, u32 p2, u32 p3, u32 p4) {
  u32 l5 = 0, l6 = 0, l7 = 0;
  u64 l8 = 0, l9 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4, i5, i6, i7;
  u64 j1;
  i0 = g0;
  i1 = 112u;
  i0 -= i1;
  l5 = i0;
  g0 = i0;
  i0 = l5;
  i1 = 0u;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l5;
  i1 = 32u;
  i0 += i1;
  i1 = 16u;
  i0 += i1;
  j1 = 0ull;
  i64_store((&memory), (u64)(i0), j1);
  i0 = l5;
  j1 = 17179869184ull;
  i64_store((&memory), (u64)(i0 + 40), j1);
  i0 = l5;
  j1 = 4ull;
  i64_store((&memory), (u64)(i0 + 32), j1);
  i0 = l5;
  i1 = 32u;
  i0 += i1;
  i1 = 1049088u;
  i2 = 3u;
  i3 = 1049091u;
  i4 = 6u;
  i5 = 3u;
  _ZN63__LT_sr_sandbox__imp__EnvironmentDefinitionBuilder_LT_T_GT__GT_13add_host_func17h50b6f5e9513eb2d0E(i0, i1, i2, i3, i4, i5);
  i0 = l5;
  i1 = 32u;
  i0 += i1;
  i1 = 1049088u;
  i2 = 3u;
  i3 = 1049097u;
  i4 = 11u;
  i5 = 4u;
  _ZN63__LT_sr_sandbox__imp__EnvironmentDefinitionBuilder_LT_T_GT__GT_13add_host_func17h50b6f5e9513eb2d0E(i0, i1, i2, i3, i4, i5);
  i0 = 1u;
  i1 = 16u;
  i0 = (*Z_envZ_ext_sandbox_memory_newZ_iii)(i0, i1);
  l6 = i0;
  i1 = 4294967295u;
  i0 = i0 == i1;
  if (i0) {goto B1;}
  i0 = 12u;
  i0 = __rust_alloc(i0);
  l7 = i0;
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = l7;
  i1 = l6;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = l7;
  j1 = 4294967297ull;
  i64_store((&memory), (u64)(i0), j1);
  i0 = 1u;
  i0 = !(i0);
  if (i0) {goto B2;}
  i0 = l7;
  i1 = 1u;
  i2 = 1u;
  i1 += i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l5;
  i1 = 32u;
  i0 += i1;
  i1 = 1049088u;
  i2 = 3u;
  i3 = 1049112u;
  i4 = 6u;
  i5 = l7;
  _ZN63__LT_sr_sandbox__imp__EnvironmentDefinitionBuilder_LT_T_GT__GT_10add_memory17h4225e8f67fd3b451E(i0, i1, i2, i3, i4, i5);
  i0 = l5;
  i1 = 8u;
  i0 += i1;
  i1 = 16u;
  i0 += i1;
  i1 = l5;
  i2 = 32u;
  i1 += i2;
  i2 = 16u;
  i1 += i2;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l5;
  i1 = 8u;
  i0 += i1;
  i1 = 8u;
  i0 += i1;
  i1 = l5;
  i2 = 32u;
  i1 += i2;
  i2 = 8u;
  i1 += i2;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l7;
  i1 = l7;
  i1 = i32_load((&memory), (u64)(i1));
  i2 = 4294967295u;
  i1 += i2;
  l6 = i1;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l5;
  i1 = l5;
  j1 = i64_load((&memory), (u64)(i1 + 32));
  i64_store((&memory), (u64)(i0 + 8), j1);
  i0 = l6;
  if (i0) {goto B3;}
  i0 = l7;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  (*Z_envZ_ext_sandbox_memory_teardownZ_vi)(i0);
  i0 = l7;
  i1 = l7;
  i1 = i32_load((&memory), (u64)(i1 + 4));
  i2 = 4294967295u;
  i1 += i2;
  l6 = i1;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l6;
  if (i0) {goto B3;}
  i0 = l7;
  __rust_dealloc(i0);
  B3:;
  i0 = l5;
  i1 = 72u;
  i0 += i1;
  i1 = l5;
  i2 = 8u;
  i1 += i2;
  _ZN12parity_codec5codec6Encode6encode17h7199eee6cd6e7a2fE(i0, i1);
  i0 = 5u;
  i1 = p1;
  i2 = p2;
  i3 = l5;
  i3 = i32_load((&memory), (u64)(i3 + 72));
  l6 = i3;
  i4 = l5;
  i4 = i32_load((&memory), (u64)(i4 + 80));
  i5 = l5;
  i6 = 4u;
  i5 += i6;
  i0 = (*Z_envZ_ext_sandbox_instantiateZ_iiiiiii)(i0, i1, i2, i3, i4, i5);
  l7 = i0;
  i1 = 2u;
  i0 |= i1;
  i1 = 4294967295u;
  i0 = i0 != i1;
  if (i0) {goto B5;}
  i0 = l5;
  i0 = i32_load((&memory), (u64)(i0 + 76));
  i0 = !(i0);
  if (i0) {goto B6;}
  i0 = l6;
  __rust_dealloc(i0);
  B6:;
  i0 = p0;
  i1 = 5u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l5;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  p1 = i0;
  i0 = l5;
  i0 = i32_load((&memory), (u64)(i0 + 16));
  l7 = i0;
  i0 = !(i0);
  if (i0) {goto B7;}
  i0 = l7;
  i1 = 5u;
  i0 <<= (i1 & 31);
  p0 = i0;
  i0 = p1;
  l7 = i0;
  L8: 
    i0 = l7;
    i1 = 4u;
    i0 += i1;
    i0 = i32_load((&memory), (u64)(i0));
    i0 = !(i0);
    if (i0) {goto B9;}
    i0 = l7;
    i0 = i32_load((&memory), (u64)(i0));
    __rust_dealloc(i0);
    B9:;
    i0 = l7;
    i1 = 16u;
    i0 += i1;
    i0 = i32_load((&memory), (u64)(i0));
    i0 = !(i0);
    if (i0) {goto B10;}
    i0 = l7;
    i1 = 12u;
    i0 += i1;
    i0 = i32_load((&memory), (u64)(i0));
    __rust_dealloc(i0);
    B10:;
    i0 = l7;
    i1 = 32u;
    i0 += i1;
    l7 = i0;
    i0 = p0;
    i1 = 4294967264u;
    i0 += i1;
    p0 = i0;
    if (i0) {goto L8;}
  B7:;
  i0 = l5;
  i0 = i32_load((&memory), (u64)(i0 + 12));
  i0 = !(i0);
  if (i0) {goto B11;}
  i0 = p1;
  __rust_dealloc(i0);
  B11:;
  i0 = l5;
  i0 = i32_load((&memory), (u64)(i0 + 20));
  p2 = i0;
  i0 = l5;
  i1 = 28u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  l7 = i0;
  i0 = !(i0);
  if (i0) {goto B12;}
  i0 = l7;
  i1 = 2u;
  i0 <<= (i1 & 31);
  p0 = i0;
  i0 = p2;
  l7 = i0;
  L13: 
    i0 = l7;
    i0 = i32_load((&memory), (u64)(i0));
    p1 = i0;
    i1 = p1;
    i1 = i32_load((&memory), (u64)(i1));
    i2 = 4294967295u;
    i1 += i2;
    i32_store((&memory), (u64)(i0), i1);
    i0 = l7;
    i0 = i32_load((&memory), (u64)(i0));
    p1 = i0;
    i0 = i32_load((&memory), (u64)(i0));
    if (i0) {goto B15;}
    i0 = p1;
    i0 = i32_load((&memory), (u64)(i0 + 8));
    (*Z_envZ_ext_sandbox_memory_teardownZ_vi)(i0);
    i0 = l7;
    i0 = i32_load((&memory), (u64)(i0));
    p1 = i0;
    i1 = p1;
    i1 = i32_load((&memory), (u64)(i1 + 4));
    i2 = 4294967295u;
    i1 += i2;
    i32_store((&memory), (u64)(i0 + 4), i1);
    i0 = l7;
    i0 = i32_load((&memory), (u64)(i0));
    p1 = i0;
    i0 = i32_load((&memory), (u64)(i0 + 4));
    i0 = !(i0);
    if (i0) {goto B14;}
    B15:;
    i0 = l7;
    i1 = 4u;
    i0 += i1;
    l7 = i0;
    i0 = p0;
    i1 = 4294967292u;
    i0 += i1;
    p0 = i0;
    if (i0) {goto L13;}
    goto B12;
    B14:;
    i0 = p1;
    __rust_dealloc(i0);
    i0 = l7;
    i1 = 4u;
    i0 += i1;
    l7 = i0;
    i0 = p0;
    i1 = 4294967292u;
    i0 += i1;
    p0 = i0;
    if (i0) {goto L13;}
  B12:;
  i0 = l5;
  i1 = 24u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  i0 = !(i0);
  if (i0) {goto B4;}
  i0 = p2;
  __rust_dealloc(i0);
  i0 = l5;
  i1 = 112u;
  i0 += i1;
  g0 = i0;
  goto Bfunc;
  B5:;
  i0 = l5;
  i1 = 32u;
  i0 += i1;
  i1 = l5;
  i2 = 8u;
  i1 += i2;
  i2 = 12u;
  i1 += i2;
  _ZN63__LT_alloc__vec__Vec_LT_T_GT__u20_as_u20_core__clone__Clone_GT_5clone17hbb9cbfdba4f2bc5fE(i0, i1);
  i0 = l5;
  i0 = i32_load((&memory), (u64)(i0 + 76));
  i0 = !(i0);
  if (i0) {goto B16;}
  i0 = l6;
  __rust_dealloc(i0);
  B16:;
  i0 = l5;
  i1 = 96u;
  i0 += i1;
  i1 = 8u;
  i0 += i1;
  p1 = i0;
  i1 = l5;
  i2 = 32u;
  i1 += i2;
  i2 = 8u;
  i1 += i2;
  p2 = i1;
  i1 = i32_load((&memory), (u64)(i1));
  i32_store((&memory), (u64)(i0), i1);
  i0 = l5;
  i1 = l5;
  j1 = i64_load((&memory), (u64)(i1 + 32));
  i64_store((&memory), (u64)(i0 + 96), j1);
  i0 = l5;
  i1 = 56u;
  i0 += i1;
  i1 = 12u;
  i0 += i1;
  i1 = p1;
  i1 = i32_load((&memory), (u64)(i1));
  i32_store((&memory), (u64)(i0), i1);
  i0 = l5;
  i1 = l7;
  i32_store((&memory), (u64)(i0 + 56), i1);
  i0 = l5;
  i1 = l5;
  j1 = i64_load((&memory), (u64)(i1 + 96));
  i64_store((&memory), (u64)(i0 + 60), j1);
  i0 = l5;
  i1 = 72u;
  i0 += i1;
  i1 = l5;
  i2 = 56u;
  i1 += i2;
  i2 = 1049108u;
  i3 = 4u;
  i4 = p3;
  i5 = p4;
  i6 = l5;
  i7 = 4u;
  i6 += i7;
  _ZN43__LT_sr_sandbox__imp__Instance_LT_T_GT__GT_6invoke17h76aac43157c22614E(i0, i1, i2, i3, i4, i5, i6);
  i0 = p2;
  i1 = l5;
  i2 = 81u;
  i1 += i2;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l5;
  i1 = 47u;
  i0 += i1;
  p2 = i0;
  i1 = l5;
  i2 = 88u;
  i1 += i2;
  j1 = i64_load((&memory), (u64)(i1));
  i64_store((&memory), (u64)(i0), j1);
  i0 = l5;
  i1 = l5;
  j1 = i64_load((&memory), (u64)(i1 + 73));
  i64_store((&memory), (u64)(i0 + 32), j1);
  i0 = l5;
  i0 = i32_load8_u((&memory), (u64)(i0 + 72));
  i1 = 1u;
  i0 = i0 != i1;
  if (i0) {goto B18;}
  i0 = p0;
  i1 = 5u;
  i32_store((&memory), (u64)(i0), i1);
  goto B17;
  B18:;
  i0 = p0;
  i1 = l5;
  j1 = i64_load((&memory), (u64)(i1 + 39));
  l8 = j1;
  i64_store((&memory), (u64)(i0), j1);
  i0 = p1;
  i1 = p2;
  j1 = i64_load((&memory), (u64)(i1));
  l9 = j1;
  i64_store((&memory), (u64)(i0), j1);
  i0 = p0;
  i1 = 8u;
  i0 += i1;
  j1 = l9;
  i64_store((&memory), (u64)(i0), j1);
  i0 = l5;
  j1 = l8;
  i64_store((&memory), (u64)(i0 + 96), j1);
  B17:;
  i0 = l7;
  (*Z_envZ_ext_sandbox_instance_teardownZ_vi)(i0);
  i0 = l5;
  i0 = i32_load((&memory), (u64)(i0 + 60));
  p2 = i0;
  i0 = l5;
  i1 = 68u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  l7 = i0;
  i0 = !(i0);
  if (i0) {goto B19;}
  i0 = l7;
  i1 = 2u;
  i0 <<= (i1 & 31);
  p0 = i0;
  i0 = p2;
  l7 = i0;
  L20: 
    i0 = l7;
    i0 = i32_load((&memory), (u64)(i0));
    p1 = i0;
    i1 = p1;
    i1 = i32_load((&memory), (u64)(i1));
    i2 = 4294967295u;
    i1 += i2;
    i32_store((&memory), (u64)(i0), i1);
    i0 = l7;
    i0 = i32_load((&memory), (u64)(i0));
    p1 = i0;
    i0 = i32_load((&memory), (u64)(i0));
    if (i0) {goto B22;}
    i0 = p1;
    i0 = i32_load((&memory), (u64)(i0 + 8));
    (*Z_envZ_ext_sandbox_memory_teardownZ_vi)(i0);
    i0 = l7;
    i0 = i32_load((&memory), (u64)(i0));
    p1 = i0;
    i1 = p1;
    i1 = i32_load((&memory), (u64)(i1 + 4));
    i2 = 4294967295u;
    i1 += i2;
    i32_store((&memory), (u64)(i0 + 4), i1);
    i0 = l7;
    i0 = i32_load((&memory), (u64)(i0));
    p1 = i0;
    i0 = i32_load((&memory), (u64)(i0 + 4));
    i0 = !(i0);
    if (i0) {goto B21;}
    B22:;
    i0 = l7;
    i1 = 4u;
    i0 += i1;
    l7 = i0;
    i0 = p0;
    i1 = 4294967292u;
    i0 += i1;
    p0 = i0;
    if (i0) {goto L20;}
    goto B19;
    B21:;
    i0 = p1;
    __rust_dealloc(i0);
    i0 = l7;
    i1 = 4u;
    i0 += i1;
    l7 = i0;
    i0 = p0;
    i1 = 4294967292u;
    i0 += i1;
    p0 = i0;
    if (i0) {goto L20;}
  B19:;
  i0 = l5;
  i1 = 64u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  i0 = !(i0);
  if (i0) {goto B23;}
  i0 = p2;
  __rust_dealloc(i0);
  B23:;
  i0 = l5;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  p1 = i0;
  i0 = l5;
  i0 = i32_load((&memory), (u64)(i0 + 16));
  l7 = i0;
  i0 = !(i0);
  if (i0) {goto B24;}
  i0 = l7;
  i1 = 5u;
  i0 <<= (i1 & 31);
  p0 = i0;
  i0 = p1;
  l7 = i0;
  L25: 
    i0 = l7;
    i1 = 4u;
    i0 += i1;
    i0 = i32_load((&memory), (u64)(i0));
    i0 = !(i0);
    if (i0) {goto B26;}
    i0 = l7;
    i0 = i32_load((&memory), (u64)(i0));
    __rust_dealloc(i0);
    B26:;
    i0 = l7;
    i1 = 16u;
    i0 += i1;
    i0 = i32_load((&memory), (u64)(i0));
    i0 = !(i0);
    if (i0) {goto B27;}
    i0 = l7;
    i1 = 12u;
    i0 += i1;
    i0 = i32_load((&memory), (u64)(i0));
    __rust_dealloc(i0);
    B27:;
    i0 = l7;
    i1 = 32u;
    i0 += i1;
    l7 = i0;
    i0 = p0;
    i1 = 4294967264u;
    i0 += i1;
    p0 = i0;
    if (i0) {goto L25;}
  B24:;
  i0 = l5;
  i0 = i32_load((&memory), (u64)(i0 + 12));
  i0 = !(i0);
  if (i0) {goto B28;}
  i0 = p1;
  __rust_dealloc(i0);
  B28:;
  i0 = l5;
  i0 = i32_load((&memory), (u64)(i0 + 20));
  p2 = i0;
  i0 = l5;
  i1 = 28u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  l7 = i0;
  i0 = !(i0);
  if (i0) {goto B29;}
  i0 = l7;
  i1 = 2u;
  i0 <<= (i1 & 31);
  p0 = i0;
  i0 = p2;
  l7 = i0;
  L30: 
    i0 = l7;
    i0 = i32_load((&memory), (u64)(i0));
    p1 = i0;
    i1 = p1;
    i1 = i32_load((&memory), (u64)(i1));
    i2 = 4294967295u;
    i1 += i2;
    i32_store((&memory), (u64)(i0), i1);
    i0 = l7;
    i0 = i32_load((&memory), (u64)(i0));
    p1 = i0;
    i0 = i32_load((&memory), (u64)(i0));
    if (i0) {goto B32;}
    i0 = p1;
    i0 = i32_load((&memory), (u64)(i0 + 8));
    (*Z_envZ_ext_sandbox_memory_teardownZ_vi)(i0);
    i0 = l7;
    i0 = i32_load((&memory), (u64)(i0));
    p1 = i0;
    i1 = p1;
    i1 = i32_load((&memory), (u64)(i1 + 4));
    i2 = 4294967295u;
    i1 += i2;
    i32_store((&memory), (u64)(i0 + 4), i1);
    i0 = l7;
    i0 = i32_load((&memory), (u64)(i0));
    p1 = i0;
    i0 = i32_load((&memory), (u64)(i0 + 4));
    i0 = !(i0);
    if (i0) {goto B31;}
    B32:;
    i0 = l7;
    i1 = 4u;
    i0 += i1;
    l7 = i0;
    i0 = p0;
    i1 = 4294967292u;
    i0 += i1;
    p0 = i0;
    if (i0) {goto L30;}
    goto B29;
    B31:;
    i0 = p1;
    __rust_dealloc(i0);
    i0 = l7;
    i1 = 4u;
    i0 += i1;
    l7 = i0;
    i0 = p0;
    i1 = 4294967292u;
    i0 += i1;
    p0 = i0;
    if (i0) {goto L30;}
  B29:;
  i0 = l5;
  i1 = 24u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  i0 = !(i0);
  if (i0) {goto B4;}
  i0 = p2;
  __rust_dealloc(i0);
  B4:;
  i0 = l5;
  i1 = 112u;
  i0 += i1;
  g0 = i0;
  goto Bfunc;
  B2:;
  UNREACHABLE;
  B1:;
  i0 = l5;
  i1 = 92u;
  i0 += i1;
  i1 = 1u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l5;
  i1 = 2u;
  i32_store((&memory), (u64)(i0 + 100), i1);
  i0 = l5;
  i1 = 1049788u;
  i32_store((&memory), (u64)(i0 + 96), i1);
  i0 = l5;
  j1 = 1ull;
  i64_store((&memory), (u64)(i0 + 76), j1);
  i0 = l5;
  i1 = 1049796u;
  i32_store((&memory), (u64)(i0 + 72), i1);
  i0 = l5;
  i1 = l5;
  i2 = 96u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 88), i1);
  i0 = l5;
  i1 = 72u;
  i0 += i1;
  i1 = 1049804u;
  _ZN4core9panicking9panic_fmt17hc562398ea080c8caE(i0, i1);
  UNREACHABLE;
  B0:;
  i0 = 12u;
  i1 = 4u;
  rust_oom(i0, i1);
  UNREACHABLE;
  Bfunc:;
  FUNC_EPILOGUE;
}

static void _ZN12runtime_test17execute_sandboxed10env_assert17h1a8e102f17474114E(u32 p0, u32 p1, u32 p2, u32 p3) {
  FUNC_PROLOGUE;
  u32 i0, i1;
  i0 = p3;
  i1 = 1u;
  i0 = i0 != i1;
  if (i0) {goto B1;}
  i0 = p2;
  i0 = i32_load((&memory), (u64)(i0));
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = p0;
  i1 = 5u;
  i32_store((&memory), (u64)(i0), i1);
  goto Bfunc;
  B1:;
  i0 = p0;
  i1 = 5u;
  i32_store((&memory), (u64)(i0), i1);
  goto Bfunc;
  B0:;
  i0 = p2;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  i0 = !(i0);
  if (i0) {goto B2;}
  i0 = p0;
  i1 = 4u;
  i32_store((&memory), (u64)(i0), i1);
  goto Bfunc;
  B2:;
  i0 = p0;
  i1 = 5u;
  i32_store((&memory), (u64)(i0), i1);
  Bfunc:;
  FUNC_EPILOGUE;
}

static void _ZN63__LT_sr_sandbox__imp__EnvironmentDefinitionBuilder_LT_T_GT__GT_13add_host_func17h50b6f5e9513eb2d0E(u32 p0, u32 p1, u32 p2, u32 p3, u32 p4, u32 p5) {
  u32 l6 = 0, l7 = 0, l8 = 0;
  u64 l9 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  u64 j0, j1;
  i0 = p2;
  i1 = 4294967295u;
  i0 = (u32)((s32)i0 <= (s32)i1);
  if (i0) {goto B2;}
  i0 = p2;
  i0 = !(i0);
  if (i0) {goto B3;}
  i0 = p2;
  i0 = __rust_alloc(i0);
  l6 = i0;
  i0 = !(i0);
  if (i0) {goto B1;}
  i0 = l6;
  i1 = p1;
  i2 = p2;
  i0 = memcpy_0(i0, i1, i2);
  i0 = p4;
  i1 = 4294967295u;
  i0 = (u32)((s32)i0 <= (s32)i1);
  if (i0) {goto B2;}
  goto B0;
  B3:;
  i0 = 1u;
  l6 = i0;
  i0 = 1u;
  i1 = p1;
  i2 = p2;
  i0 = memcpy_0(i0, i1, i2);
  i0 = p4;
  i1 = 4294967295u;
  i0 = (u32)((s32)i0 > (s32)i1);
  if (i0) {goto B0;}
  B2:;
  _ZN49__LT_alloc__raw_vec__RawVec_LT_T_C__u20_A_GT__GT_11allocate_in28__u7b__u7b_closure_u7d__u7d_17h13224a7a8fe42f97E();
  UNREACHABLE;
  B1:;
  i0 = p2;
  i1 = 1u;
  rust_oom(i0, i1);
  UNREACHABLE;
  B0:;
  i0 = p4;
  i0 = !(i0);
  if (i0) {goto B5;}
  i0 = p4;
  i0 = __rust_alloc(i0);
  p1 = i0;
  if (i0) {goto B4;}
  i0 = p4;
  i1 = 1u;
  rust_oom(i0, i1);
  UNREACHABLE;
  B5:;
  i0 = 1u;
  p1 = i0;
  B4:;
  i0 = p1;
  i1 = p3;
  i2 = p4;
  i0 = memcpy_0(i0, i1, i2);
  p3 = i0;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  p1 = i0;
  i1 = p0;
  i2 = 4u;
  i1 += i2;
  i1 = i32_load((&memory), (u64)(i1));
  i0 = i0 != i1;
  if (i0) {goto B6;}
  i0 = p1;
  i1 = 1u;
  i0 += i1;
  l7 = i0;
  i1 = p1;
  i0 = i0 < i1;
  if (i0) {goto B8;}
  i0 = p1;
  i1 = 1u;
  i0 <<= (i1 & 31);
  l8 = i0;
  i1 = l7;
  i2 = l7;
  i3 = l8;
  i2 = i2 < i3;
  i0 = i2 ? i0 : i1;
  l7 = i0;
  j0 = (u64)(i0);
  j1 = 5ull;
  j0 <<= (j1 & 63);
  l9 = j0;
  j1 = 32ull;
  j0 >>= (j1 & 63);
  i0 = (u32)(j0);
  if (i0) {goto B8;}
  j0 = l9;
  i0 = (u32)(j0);
  l8 = i0;
  i1 = 0u;
  i0 = (u32)((s32)i0 < (s32)i1);
  if (i0) {goto B8;}
  i0 = p1;
  i0 = !(i0);
  if (i0) {goto B10;}
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p1;
  i2 = 5u;
  i1 <<= (i2 & 31);
  i2 = l8;
  i0 = __rust_realloc(i0, i1, i2);
  p1 = i0;
  i0 = !(i0);
  if (i0) {goto B9;}
  goto B7;
  B10:;
  i0 = l8;
  i0 = __rust_alloc(i0);
  p1 = i0;
  if (i0) {goto B7;}
  B9:;
  i0 = l8;
  i1 = 4u;
  rust_oom(i0, i1);
  UNREACHABLE;
  B8:;
  _ZN5alloc7raw_vec17capacity_overflow17h05ed4d24a03bca6bE();
  UNREACHABLE;
  B7:;
  i0 = p0;
  i1 = p1;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = 4u;
  i0 += i1;
  i1 = l7;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = 8u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  p1 = i0;
  B6:;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p1;
  i2 = 5u;
  i1 <<= (i2 & 31);
  i0 += i1;
  p1 = i0;
  i1 = 0u;
  i32_store((&memory), (u64)(i0 + 24), i1);
  i0 = p1;
  i1 = p3;
  i32_store((&memory), (u64)(i0 + 12), i1);
  i0 = p1;
  i1 = p2;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = p1;
  i1 = p2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = p1;
  i1 = l6;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p1;
  i1 = 28u;
  i0 += i1;
  i1 = p5;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p1;
  i1 = 20u;
  i0 += i1;
  i1 = p4;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p1;
  i1 = 16u;
  i0 += i1;
  i1 = p4;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = 8u;
  i0 += i1;
  p1 = i0;
  i1 = p1;
  i1 = i32_load((&memory), (u64)(i1));
  i2 = 1u;
  i1 += i2;
  i32_store((&memory), (u64)(i0), i1);
  FUNC_EPILOGUE;
}

static void _ZN12runtime_test17execute_sandboxed15env_inc_counter17h43632cbfffd814eeE(u32 p0, u32 p1, u32 p2, u32 p3) {
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  i0 = p3;
  i1 = 1u;
  i0 = i0 != i1;
  if (i0) {goto B1;}
  i0 = p2;
  i0 = i32_load((&memory), (u64)(i0));
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = p0;
  i1 = 5u;
  i32_store((&memory), (u64)(i0), i1);
  goto Bfunc;
  B1:;
  i0 = p0;
  i1 = 5u;
  i32_store((&memory), (u64)(i0), i1);
  goto Bfunc;
  B0:;
  i0 = p0;
  i1 = 0u;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p1;
  i1 = p1;
  i1 = i32_load((&memory), (u64)(i1));
  i2 = p2;
  i2 = i32_load((&memory), (u64)(i2 + 4));
  i1 += i2;
  p3 = i1;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = p3;
  i32_store((&memory), (u64)(i0 + 4), i1);
  Bfunc:;
  FUNC_EPILOGUE;
}

static void _ZN63__LT_sr_sandbox__imp__EnvironmentDefinitionBuilder_LT_T_GT__GT_10add_memory17h4225e8f67fd3b451E(u32 p0, u32 p1, u32 p2, u32 p3, u32 p4, u32 p5) {
  u32 l6 = 0, l7 = 0, l8 = 0, l9 = 0;
  u64 l10 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  u64 j0, j1;
  i0 = p5;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = 1u;
  i0 += i1;
  l6 = i0;
  i1 = 1u;
  i0 = i0 <= i1;
  if (i0) {goto B7;}
  i0 = p5;
  i1 = l6;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = 20u;
  i0 += i1;
  l7 = i0;
  i0 = i32_load((&memory), (u64)(i0));
  l6 = i0;
  i1 = p0;
  i2 = 16u;
  i1 += i2;
  i1 = i32_load((&memory), (u64)(i1));
  i0 = i0 != i1;
  if (i0) {goto B5;}
  i0 = l6;
  i1 = 1u;
  i0 += i1;
  l8 = i0;
  i1 = l6;
  i0 = i0 < i1;
  if (i0) {goto B4;}
  i0 = l6;
  i1 = 1u;
  i0 <<= (i1 & 31);
  l9 = i0;
  i1 = l8;
  i2 = l8;
  i3 = l9;
  i2 = i2 < i3;
  i0 = i2 ? i0 : i1;
  l8 = i0;
  j0 = (u64)(i0);
  j1 = 2ull;
  j0 <<= (j1 & 63);
  l10 = j0;
  j1 = 32ull;
  j0 >>= (j1 & 63);
  i0 = (u32)(j0);
  if (i0) {goto B4;}
  j0 = l10;
  i0 = (u32)(j0);
  l9 = i0;
  i1 = 0u;
  i0 = (u32)((s32)i0 < (s32)i1);
  if (i0) {goto B4;}
  i0 = l6;
  i0 = !(i0);
  if (i0) {goto B9;}
  i0 = p0;
  i1 = 12u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = l6;
  i2 = 2u;
  i1 <<= (i2 & 31);
  i2 = l9;
  i0 = __rust_realloc(i0, i1, i2);
  l6 = i0;
  i0 = !(i0);
  if (i0) {goto B8;}
  goto B6;
  B9:;
  i0 = l9;
  i0 = __rust_alloc(i0);
  l6 = i0;
  if (i0) {goto B6;}
  B8:;
  i0 = l9;
  i1 = 4u;
  rust_oom(i0, i1);
  UNREACHABLE;
  B7:;
  UNREACHABLE;
  B6:;
  i0 = p0;
  i1 = 16u;
  i0 += i1;
  i1 = l8;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = 12u;
  i0 += i1;
  i1 = l6;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = 20u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  l6 = i0;
  B5:;
  i0 = p0;
  i1 = 12u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = l6;
  i2 = 2u;
  i1 <<= (i2 & 31);
  i0 += i1;
  i1 = p5;
  i32_store((&memory), (u64)(i0), i1);
  i0 = 1u;
  l6 = i0;
  i0 = l7;
  i1 = l7;
  i1 = i32_load((&memory), (u64)(i1));
  i2 = 1u;
  i1 += i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p2;
  i1 = 4294967295u;
  i0 = (u32)((s32)i0 <= (s32)i1);
  if (i0) {goto B3;}
  i0 = p5;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  l7 = i0;
  i0 = p2;
  i0 = !(i0);
  if (i0) {goto B10;}
  i0 = p2;
  i0 = __rust_alloc(i0);
  l6 = i0;
  i0 = !(i0);
  if (i0) {goto B2;}
  B10:;
  i0 = l6;
  i1 = p1;
  i2 = p2;
  i0 = memcpy_0(i0, i1, i2);
  p1 = i0;
  i0 = p4;
  i1 = 4294967295u;
  i0 = (u32)((s32)i0 <= (s32)i1);
  if (i0) {goto B3;}
  i0 = p4;
  i0 = !(i0);
  if (i0) {goto B12;}
  i0 = p4;
  i0 = __rust_alloc(i0);
  l6 = i0;
  if (i0) {goto B11;}
  i0 = p4;
  i1 = 1u;
  rust_oom(i0, i1);
  UNREACHABLE;
  B12:;
  i0 = 1u;
  l6 = i0;
  B11:;
  i0 = l6;
  i1 = p3;
  i2 = p4;
  i0 = memcpy_0(i0, i1, i2);
  p3 = i0;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0 + 8));
  l6 = i0;
  i1 = p0;
  i2 = 4u;
  i1 += i2;
  i1 = i32_load((&memory), (u64)(i1));
  i0 = i0 != i1;
  if (i0) {goto B0;}
  i0 = l6;
  i1 = 1u;
  i0 += i1;
  l8 = i0;
  i1 = l6;
  i0 = i0 < i1;
  if (i0) {goto B4;}
  i0 = l6;
  i1 = 1u;
  i0 <<= (i1 & 31);
  l9 = i0;
  i1 = l8;
  i2 = l8;
  i3 = l9;
  i2 = i2 < i3;
  i0 = i2 ? i0 : i1;
  l8 = i0;
  j0 = (u64)(i0);
  j1 = 5ull;
  j0 <<= (j1 & 63);
  l10 = j0;
  j1 = 32ull;
  j0 >>= (j1 & 63);
  i0 = (u32)(j0);
  if (i0) {goto B4;}
  j0 = l10;
  i0 = (u32)(j0);
  l9 = i0;
  i1 = 0u;
  i0 = (u32)((s32)i0 < (s32)i1);
  if (i0) {goto B4;}
  i0 = l6;
  i0 = !(i0);
  if (i0) {goto B14;}
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = l6;
  i2 = 5u;
  i1 <<= (i2 & 31);
  i2 = l9;
  i0 = __rust_realloc(i0, i1, i2);
  l6 = i0;
  i0 = !(i0);
  if (i0) {goto B13;}
  goto B1;
  B14:;
  i0 = l9;
  i0 = __rust_alloc(i0);
  l6 = i0;
  if (i0) {goto B1;}
  B13:;
  i0 = l9;
  i1 = 4u;
  rust_oom(i0, i1);
  UNREACHABLE;
  B4:;
  _ZN5alloc7raw_vec17capacity_overflow17h05ed4d24a03bca6bE();
  UNREACHABLE;
  B3:;
  _ZN49__LT_alloc__raw_vec__RawVec_LT_T_C__u20_A_GT__GT_11allocate_in28__u7b__u7b_closure_u7d__u7d_17h13224a7a8fe42f97E();
  UNREACHABLE;
  B2:;
  i0 = p2;
  i1 = 1u;
  rust_oom(i0, i1);
  UNREACHABLE;
  B1:;
  i0 = p0;
  i1 = l6;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = 4u;
  i0 += i1;
  i1 = l8;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = 8u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  l6 = i0;
  B0:;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = l6;
  i2 = 5u;
  i1 <<= (i2 & 31);
  i0 += i1;
  l6 = i0;
  i1 = 1u;
  i32_store((&memory), (u64)(i0 + 24), i1);
  i0 = l6;
  i1 = p3;
  i32_store((&memory), (u64)(i0 + 12), i1);
  i0 = l6;
  i1 = p2;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = l6;
  i1 = p2;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l6;
  i1 = p1;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l6;
  i1 = 28u;
  i0 += i1;
  i1 = l7;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l6;
  i1 = 20u;
  i0 += i1;
  i1 = p4;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l6;
  i1 = 16u;
  i0 += i1;
  i1 = p4;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = 8u;
  i0 += i1;
  p0 = i0;
  i1 = p0;
  i1 = i32_load((&memory), (u64)(i1));
  i2 = 1u;
  i1 += i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p5;
  i1 = p5;
  i1 = i32_load((&memory), (u64)(i1));
  i2 = 4294967295u;
  i1 += i2;
  p0 = i1;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  if (i0) {goto B16;}
  i0 = p5;
  i1 = 8u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  (*Z_envZ_ext_sandbox_memory_teardownZ_vi)(i0);
  i0 = p5;
  i1 = p5;
  i1 = i32_load((&memory), (u64)(i1 + 4));
  i2 = 4294967295u;
  i1 += i2;
  p0 = i1;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = p0;
  i0 = !(i0);
  if (i0) {goto B15;}
  B16:;
  goto Bfunc;
  B15:;
  i0 = p5;
  __rust_dealloc(i0);
  Bfunc:;
  FUNC_EPILOGUE;
}

static u64 _ZN10sr_sandbox3imp14dispatch_thunk17hd12b2ae46f5bc54cE(u32 p0, u32 p1, u32 p2, u32 p3) {
  u32 l4 = 0;
  u64 l5 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4;
  u64 j0, j1;
  i0 = g0;
  i1 = 32u;
  i0 -= i1;
  l4 = i0;
  g0 = i0;
  i0 = l4;
  i1 = p1;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l4;
  i1 = p0;
  i2 = 1049368u;
  i3 = p1;
  i1 = i3 ? i1 : i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l4;
  i1 = 16u;
  i0 += i1;
  i1 = l4;
  _ZN72__LT_alloc__vec__Vec_LT_T_GT__u20_as_u20_parity_codec__codec__Decode_GT_6decode17hc89f3b72474bfd56E(i0, i1);
  i0 = l4;
  i0 = i32_load((&memory), (u64)(i0 + 16));
  p1 = i0;
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = l4;
  i0 = i32_load((&memory), (u64)(i0 + 20));
  p0 = i0;
  i0 = l4;
  i1 = 16u;
  i0 += i1;
  i1 = p2;
  i2 = p1;
  i3 = l4;
  i4 = 24u;
  i3 += i4;
  i3 = i32_load((&memory), (u64)(i3));
  i4 = p3;
  CALL_INDIRECT(__indirect_function_table, void (*)(u32, u32, u32, u32), 2, i4, i0, i1, i2, i3);
  i0 = l4;
  i1 = l4;
  i2 = 16u;
  i1 += i2;
  _ZN12parity_codec5codec6Encode6encode17ha70755ab770d169bE(i0, i1);
  i0 = l4;
  j0 = i64_load32_u((&memory), (u64)(i0));
  j1 = 32ull;
  j0 <<= (j1 & 63);
  i1 = l4;
  j1 = i64_load32_u((&memory), (u64)(i1 + 8));
  j0 |= j1;
  l5 = j0;
  i0 = p0;
  i0 = !(i0);
  if (i0) {goto B1;}
  i0 = p1;
  __rust_dealloc(i0);
  B1:;
  i0 = l4;
  i1 = 32u;
  i0 += i1;
  g0 = i0;
  j0 = l5;
  goto Bfunc;
  B0:;
  _ZN4core6option13expect_failed17he3f99b0653a0c0b7E();
  UNREACHABLE;
  Bfunc:;
  FUNC_EPILOGUE;
  return j0;
}

static void _ZN43__LT_sr_sandbox__imp__Instance_LT_T_GT__GT_6invoke17h76aac43157c22614E(u32 p0, u32 p1, u32 p2, u32 p3, u32 p4, u32 p5, u32 p6) {
  u32 l7 = 0, l9 = 0, l10 = 0, l11 = 0, l12 = 0;
  u64 l8 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4, i5, i6, i7;
  u64 j0, j1;
  i0 = g0;
  i1 = 80u;
  i0 -= i1;
  l7 = i0;
  g0 = i0;
  i0 = p5;
  j0 = (u64)(i0);
  l8 = j0;
  j1 = 28ull;
  j0 >>= (j1 & 63);
  i0 = (u32)(j0);
  if (i0) {goto B10;}
  j0 = l8;
  j1 = 4ull;
  j0 <<= (j1 & 63);
  i0 = (u32)(j0);
  l9 = i0;
  i1 = 4294967295u;
  i0 = (u32)((s32)i0 <= (s32)i1);
  if (i0) {goto B10;}
  i0 = l9;
  i0 = !(i0);
  if (i0) {goto B12;}
  i0 = l9;
  i0 = __rust_alloc(i0);
  l10 = i0;
  if (i0) {goto B11;}
  i0 = l9;
  i1 = 8u;
  rust_oom(i0, i1);
  UNREACHABLE;
  B12:;
  i0 = 8u;
  l10 = i0;
  B11:;
  i0 = l10;
  i1 = p4;
  i2 = p5;
  i3 = 4u;
  i2 <<= (i3 & 31);
  i0 = memcpy_0(i0, i1, i2);
  p4 = i0;
  i0 = l7;
  i1 = 0u;
  i32_store((&memory), (u64)(i0 + 56), i1);
  i0 = l7;
  j1 = 1ull;
  i64_store((&memory), (u64)(i0 + 48), j1);
  i0 = p5;
  i1 = 63u;
  i0 = i0 > i1;
  if (i0) {goto B15;}
  i0 = 1u;
  i0 = __rust_alloc(i0);
  l9 = i0;
  i0 = !(i0);
  if (i0) {goto B7;}
  i0 = l7;
  i1 = 1u;
  i32_store((&memory), (u64)(i0 + 52), i1);
  i0 = l7;
  i1 = 56u;
  i0 += i1;
  l10 = i0;
  i1 = l10;
  i1 = i32_load((&memory), (u64)(i1));
  l11 = i1;
  i2 = 1u;
  i1 += i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l7;
  i1 = l9;
  i32_store((&memory), (u64)(i0 + 48), i1);
  i0 = l9;
  i1 = l11;
  i0 += i1;
  i1 = p5;
  i2 = 2u;
  i1 <<= (i2 & 31);
  i32_store8((&memory), (u64)(i0), i1);
  i0 = p5;
  if (i0) {goto B14;}
  i0 = l10;
  i0 = i32_load((&memory), (u64)(i0));
  l11 = i0;
  i0 = l7;
  i0 = i32_load((&memory), (u64)(i0 + 52));
  l12 = i0;
  i0 = l7;
  i0 = i32_load((&memory), (u64)(i0 + 48));
  l10 = i0;
  i0 = 10u;
  p4 = i0;
  i0 = 10u;
  i0 = __rust_alloc_zeroed(i0);
  l9 = i0;
  if (i0) {goto B13;}
  goto B9;
  B15:;
  i0 = p5;
  i1 = 16384u;
  i0 = i0 >= i1;
  if (i0) {goto B16;}
  i0 = 2u;
  i0 = __rust_alloc(i0);
  l9 = i0;
  i0 = !(i0);
  if (i0) {goto B6;}
  i0 = l7;
  i1 = 2u;
  i32_store((&memory), (u64)(i0 + 52), i1);
  i0 = l7;
  i1 = 56u;
  i0 += i1;
  l10 = i0;
  i1 = l10;
  i1 = i32_load((&memory), (u64)(i1));
  l10 = i1;
  i2 = 2u;
  i1 += i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l7;
  i1 = l9;
  i32_store((&memory), (u64)(i0 + 48), i1);
  i0 = l9;
  i1 = l10;
  i0 += i1;
  i1 = p5;
  i2 = 2u;
  i1 <<= (i2 & 31);
  i2 = 1u;
  i1 |= i2;
  i32_store16((&memory), (u64)(i0), i1);
  goto B14;
  B16:;
  i0 = p5;
  i1 = 1073741824u;
  i0 = i0 >= i1;
  if (i0) {goto B17;}
  i0 = 4u;
  i0 = __rust_alloc(i0);
  l9 = i0;
  i0 = !(i0);
  if (i0) {goto B5;}
  i0 = l7;
  i1 = 4u;
  i32_store((&memory), (u64)(i0 + 52), i1);
  i0 = l7;
  i1 = 56u;
  i0 += i1;
  l10 = i0;
  i1 = l10;
  i1 = i32_load((&memory), (u64)(i1));
  l10 = i1;
  i2 = 4u;
  i1 += i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l7;
  i1 = l9;
  i32_store((&memory), (u64)(i0 + 48), i1);
  i0 = l9;
  i1 = l10;
  i0 += i1;
  i1 = p5;
  i2 = 2u;
  i1 <<= (i2 & 31);
  i2 = 2u;
  i1 |= i2;
  i32_store((&memory), (u64)(i0), i1);
  goto B14;
  B17:;
  i0 = 1u;
  i0 = __rust_alloc(i0);
  l9 = i0;
  i0 = !(i0);
  if (i0) {goto B4;}
  i0 = l7;
  i1 = 1u;
  i32_store((&memory), (u64)(i0 + 52), i1);
  i0 = l7;
  i1 = 56u;
  i0 += i1;
  l10 = i0;
  i1 = l10;
  i1 = i32_load((&memory), (u64)(i1));
  l11 = i1;
  i2 = 1u;
  i1 += i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l7;
  i1 = l9;
  i32_store((&memory), (u64)(i0 + 48), i1);
  i0 = l9;
  i1 = l11;
  i0 += i1;
  i1 = 3u;
  i32_store8((&memory), (u64)(i0), i1);
  i0 = l7;
  i0 = i32_load((&memory), (u64)(i0 + 52));
  l11 = i0;
  i1 = l10;
  i1 = i32_load((&memory), (u64)(i1));
  l9 = i1;
  i0 -= i1;
  i1 = 4u;
  i0 = i0 >= i1;
  if (i0) {goto B21;}
  i0 = l9;
  i1 = 4u;
  i0 += i1;
  l10 = i0;
  i1 = l9;
  i0 = i0 < i1;
  if (i0) {goto B3;}
  i0 = l11;
  i1 = 1u;
  i0 <<= (i1 & 31);
  l9 = i0;
  i1 = l10;
  i2 = l10;
  i3 = l9;
  i2 = i2 < i3;
  i0 = i2 ? i0 : i1;
  l9 = i0;
  i1 = 0u;
  i0 = (u32)((s32)i0 < (s32)i1);
  if (i0) {goto B3;}
  i0 = l11;
  i0 = !(i0);
  if (i0) {goto B20;}
  i0 = l7;
  i0 = i32_load((&memory), (u64)(i0 + 48));
  i1 = l11;
  i2 = l9;
  i0 = __rust_realloc(i0, i1, i2);
  l10 = i0;
  if (i0) {goto B19;}
  goto B2;
  B21:;
  i0 = l7;
  i0 = i32_load((&memory), (u64)(i0 + 48));
  l10 = i0;
  goto B18;
  B20:;
  i0 = l9;
  i0 = __rust_alloc(i0);
  l10 = i0;
  i0 = !(i0);
  if (i0) {goto B2;}
  B19:;
  i0 = l7;
  i1 = l9;
  i32_store((&memory), (u64)(i0 + 52), i1);
  i0 = l7;
  i1 = l10;
  i32_store((&memory), (u64)(i0 + 48), i1);
  i0 = l7;
  i1 = 56u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  l9 = i0;
  B18:;
  i0 = l7;
  i1 = 56u;
  i0 += i1;
  i1 = l9;
  i2 = 4u;
  i1 += i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l10;
  i1 = l9;
  i0 += i1;
  i1 = p5;
  i32_store((&memory), (u64)(i0), i1);
  B14:;
  i0 = p5;
  i1 = 4u;
  i0 <<= (i1 & 31);
  l10 = i0;
  i0 = 0u;
  l9 = i0;
  L22: 
    i0 = p4;
    i1 = l9;
    i0 += i1;
    i1 = l7;
    i2 = 48u;
    i1 += i2;
    _ZN20substrate_primitives7sandbox27_IMPL_ENCODE_FOR_TypedValue99__LT_impl_u20_parity_codec__codec__Encode_u20_for_u20_substrate_primitives__sandbox__TypedValue_GT_9encode_to17h055d1be133032210E(i0, i1);
    i0 = l10;
    i1 = l9;
    i2 = 16u;
    i1 += i2;
    l9 = i1;
    i0 = i0 != i1;
    if (i0) {goto L22;}
  i0 = l7;
  i1 = 56u;
  i0 += i1;
  i0 = i32_load((&memory), (u64)(i0));
  l11 = i0;
  i0 = l7;
  i0 = i32_load((&memory), (u64)(i0 + 52));
  l12 = i0;
  i0 = l7;
  i0 = i32_load((&memory), (u64)(i0 + 48));
  l10 = i0;
  i0 = p5;
  i0 = !(i0);
  if (i0) {goto B23;}
  i0 = p4;
  __rust_dealloc(i0);
  B23:;
  i0 = 10u;
  p4 = i0;
  i0 = 10u;
  i0 = __rust_alloc_zeroed(i0);
  l9 = i0;
  i0 = !(i0);
  if (i0) {goto B9;}
  B13:;
  i0 = p1;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = p2;
  i2 = p3;
  i3 = l10;
  i4 = l11;
  i5 = l9;
  i6 = p4;
  i7 = p6;
  i0 = (*Z_envZ_ext_sandbox_invokeZ_iiiiiiiii)(i0, i1, i2, i3, i4, i5, i6, i7);
  p4 = i0;
  i1 = 4294967293u;
  i0 = i0 == i1;
  if (i0) {goto B26;}
  i0 = p4;
  if (i0) {goto B8;}
  i0 = l7;
  i1 = 9u;
  i32_store((&memory), (u64)(i0 + 44), i1);
  i0 = l7;
  i1 = l9;
  i2 = 1u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 40), i1);
  i0 = l9;
  i0 = i32_load8_u((&memory), (u64)(i0));
  p4 = i0;
  i0 = !(i0);
  if (i0) {goto B25;}
  i0 = p4;
  i1 = 1u;
  i0 = i0 != i1;
  if (i0) {goto B27;}
  i0 = l7;
  i1 = 48u;
  i0 += i1;
  i1 = l7;
  i2 = 40u;
  i1 += i2;
  _ZN20substrate_primitives7sandbox27_IMPL_DECODE_FOR_TypedValue99__LT_impl_u20_parity_codec__codec__Decode_u20_for_u20_substrate_primitives__sandbox__TypedValue_GT_6decode17h4f4943e22d0021b4E(i0, i1);
  i0 = l7;
  i1 = 64u;
  i0 += i1;
  i1 = 8u;
  i0 += i1;
  p5 = i0;
  i1 = l7;
  i2 = 60u;
  i1 += i2;
  i1 = i32_load((&memory), (u64)(i1));
  i32_store((&memory), (u64)(i0), i1);
  i0 = l7;
  i1 = l7;
  j1 = i64_load((&memory), (u64)(i1 + 52));
  i64_store((&memory), (u64)(i0 + 64), j1);
  i0 = l7;
  i0 = i32_load((&memory), (u64)(i0 + 48));
  p4 = i0;
  i1 = 4u;
  i0 = i0 == i1;
  if (i0) {goto B27;}
  i0 = l7;
  i1 = 24u;
  i0 += i1;
  i1 = 8u;
  i0 += i1;
  i1 = p5;
  i1 = i32_load((&memory), (u64)(i1));
  i32_store((&memory), (u64)(i0), i1);
  i0 = l7;
  i1 = l7;
  j1 = i64_load((&memory), (u64)(i1 + 64));
  i64_store((&memory), (u64)(i0 + 24), j1);
  i0 = p4;
  i1 = 5u;
  i0 = i0 != i1;
  if (i0) {goto B24;}
  B27:;
  i0 = p0;
  i1 = 513u;
  i32_store16((&memory), (u64)(i0), i1);
  i0 = l9;
  __rust_dealloc(i0);
  i0 = l12;
  if (i0) {goto B1;}
  goto B0;
  B26:;
  i0 = p0;
  i1 = 513u;
  i32_store16((&memory), (u64)(i0), i1);
  i0 = l9;
  __rust_dealloc(i0);
  i0 = l12;
  i0 = !(i0);
  if (i0) {goto B0;}
  goto B1;
  B25:;
  i0 = 4u;
  p4 = i0;
  B24:;
  i0 = l7;
  i1 = 8u;
  i0 += i1;
  i1 = 8u;
  i0 += i1;
  p5 = i0;
  i1 = l7;
  i2 = 24u;
  i1 += i2;
  i2 = 8u;
  i1 += i2;
  i1 = i32_load((&memory), (u64)(i1));
  i32_store((&memory), (u64)(i0), i1);
  i0 = l7;
  i1 = l7;
  j1 = i64_load((&memory), (u64)(i1 + 24));
  i64_store((&memory), (u64)(i0 + 8), j1);
  i0 = p0;
  i1 = 8u;
  i0 += i1;
  i1 = p4;
  i32_store((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = 0u;
  i32_store8((&memory), (u64)(i0), i1);
  i0 = p0;
  i1 = 12u;
  i0 += i1;
  i1 = l7;
  j1 = i64_load((&memory), (u64)(i1 + 8));
  i64_store((&memory), (u64)(i0), j1);
  i0 = p0;
  i1 = 20u;
  i0 += i1;
  i1 = p5;
  i1 = i32_load((&memory), (u64)(i1));
  i32_store((&memory), (u64)(i0), i1);
  i0 = l9;
  __rust_dealloc(i0);
  i0 = l12;
  if (i0) {goto B1;}
  goto B0;
  B10:;
  _ZN49__LT_alloc__raw_vec__RawVec_LT_T_C__u20_A_GT__GT_11allocate_in28__u7b__u7b_closure_u7d__u7d_17h13224a7a8fe42f97E();
  UNREACHABLE;
  B9:;
  i0 = p4;
  i1 = 1u;
  rust_oom(i0, i1);
  UNREACHABLE;
  B8:;
  i0 = 1049820u;
  _ZN4core9panicking5panic17hc8c3dd99127c917dE(i0);
  UNREACHABLE;
  B7:;
  i0 = 1u;
  i1 = 1u;
  rust_oom(i0, i1);
  UNREACHABLE;
  B6:;
  i0 = 2u;
  i1 = 1u;
  rust_oom(i0, i1);
  UNREACHABLE;
  B5:;
  i0 = 4u;
  i1 = 1u;
  rust_oom(i0, i1);
  UNREACHABLE;
  B4:;
  i0 = 1u;
  i1 = 1u;
  rust_oom(i0, i1);
  UNREACHABLE;
  B3:;
  _ZN5alloc7raw_vec17capacity_overflow17h05ed4d24a03bca6bE();
  UNREACHABLE;
  B2:;
  i0 = l9;
  i1 = 1u;
  rust_oom(i0, i1);
  UNREACHABLE;
  B1:;
  i0 = l10;
  __rust_dealloc(i0);
  B0:;
  i0 = l7;
  i1 = 80u;
  i0 += i1;
  g0 = i0;
  FUNC_EPILOGUE;
}

static u64 test_sandbox_args(u32 p0, u32 p1) {
  u32 l2 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4;
  u64 j0, j1;
  i0 = g0;
  i1 = 16u;
  i0 -= i1;
  l2 = i0;
  g0 = i0;
  i0 = l2;
  i1 = p0;
  i2 = 1049368u;
  i3 = p1;
  i1 = i3 ? i1 : i2;
  i2 = p1;
  i3 = 1049320u;
  i4 = 2u;
  _ZN12runtime_test17execute_sandboxed17h7fa747205b7314a3E(i0, i1, i2, i3, i4);
  i0 = l2;
  i0 = i32_load((&memory), (u64)(i0));
  p0 = i0;
  i0 = 1u;
  i0 = __rust_alloc(i0);
  p1 = i0;
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = p1;
  i1 = p0;
  i2 = 5u;
  i1 = i1 != i2;
  i32_store8((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = 16u;
  i0 += i1;
  g0 = i0;
  i0 = p1;
  j0 = (u64)(i0);
  j1 = 4294967296ull;
  j0 |= j1;
  goto Bfunc;
  B0:;
  i0 = 1u;
  i1 = 1u;
  rust_oom(i0, i1);
  UNREACHABLE;
  Bfunc:;
  FUNC_EPILOGUE;
  return j0;
}

static u64 test_sandbox_return_val(u32 p0, u32 p1) {
  u32 l2 = 0, l3 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4;
  u64 j0, j1;
  i0 = g0;
  i1 = 16u;
  i0 -= i1;
  l2 = i0;
  g0 = i0;
  i0 = l2;
  i1 = p0;
  i2 = 1049368u;
  i3 = p1;
  i1 = i3 ? i1 : i2;
  i2 = p1;
  i3 = 1049352u;
  i4 = 1u;
  _ZN12runtime_test17execute_sandboxed17h7fa747205b7314a3E(i0, i1, i2, i3, i4);
  i0 = l2;
  i0 = i32_load((&memory), (u64)(i0 + 4));
  p0 = i0;
  i0 = l2;
  i0 = i32_load((&memory), (u64)(i0));
  l3 = i0;
  i0 = 1u;
  i0 = __rust_alloc(i0);
  p1 = i0;
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = p1;
  i1 = l3;
  i1 = !(i1);
  i2 = p0;
  i3 = 4919u;
  i2 = i2 == i3;
  i1 &= i2;
  i32_store8((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = 16u;
  i0 += i1;
  g0 = i0;
  i0 = p1;
  j0 = (u64)(i0);
  j1 = 4294967296ull;
  j0 |= j1;
  goto Bfunc;
  B0:;
  i0 = 1u;
  i1 = 1u;
  rust_oom(i0, i1);
  UNREACHABLE;
  Bfunc:;
  FUNC_EPILOGUE;
  return j0;
}

static u64 test_sandbox_instantiate(u32 p0, u32 p1) {
  u32 l2 = 0, l3 = 0, l4 = 0, l5 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4, i5, i6;
  u64 j0, j1;
  i0 = g0;
  i1 = 64u;
  i0 -= i1;
  l2 = i0;
  g0 = i0;
  i0 = l2;
  i1 = 16u;
  i0 += i1;
  j1 = 0ull;
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  j1 = 17179869184ull;
  i64_store((&memory), (u64)(i0 + 8), j1);
  i0 = l2;
  j1 = 4ull;
  i64_store((&memory), (u64)(i0), j1);
  i0 = l2;
  i1 = 24u;
  i0 += i1;
  i1 = l2;
  _ZN12parity_codec5codec6Encode6encode17h7199eee6cd6e7a2fE(i0, i1);
  i0 = 6u;
  i1 = p0;
  i2 = 1049368u;
  i3 = p1;
  i1 = i3 ? i1 : i2;
  i2 = p1;
  i3 = l2;
  i3 = i32_load((&memory), (u64)(i3 + 24));
  p0 = i3;
  i4 = l2;
  i4 = i32_load((&memory), (u64)(i4 + 32));
  i5 = l2;
  i6 = 56u;
  i5 += i6;
  i0 = (*Z_envZ_ext_sandbox_instantiateZ_iiiiiii)(i0, i1, i2, i3, i4, i5);
  p1 = i0;
  i1 = 4294967295u;
  i0 = i0 == i1;
  if (i0) {goto B5;}
  i0 = p1;
  i1 = 4294967293u;
  i0 = i0 != i1;
  if (i0) {goto B4;}
  i0 = 16u;
  p1 = i0;
  i0 = l2;
  i0 = i32_load((&memory), (u64)(i0 + 28));
  i0 = !(i0);
  if (i0) {goto B2;}
  goto B3;
  B5:;
  i0 = 0u;
  p1 = i0;
  i0 = l2;
  i0 = i32_load((&memory), (u64)(i0 + 28));
  if (i0) {goto B3;}
  goto B2;
  B4:;
  i0 = l2;
  i1 = 40u;
  i0 += i1;
  i1 = l2;
  i2 = 12u;
  i1 += i2;
  _ZN63__LT_alloc__vec__Vec_LT_T_GT__u20_as_u20_core__clone__Clone_GT_5clone17hbb9cbfdba4f2bc5fE(i0, i1);
  i0 = l2;
  i0 = i32_load((&memory), (u64)(i0 + 48));
  l3 = i0;
  i0 = l2;
  i0 = i32_load((&memory), (u64)(i0 + 44));
  l4 = i0;
  i0 = l2;
  i0 = i32_load((&memory), (u64)(i0 + 40));
  l5 = i0;
  i0 = l2;
  i0 = i32_load((&memory), (u64)(i0 + 28));
  i0 = !(i0);
  if (i0) {goto B6;}
  i0 = p0;
  __rust_dealloc(i0);
  B6:;
  i0 = p1;
  (*Z_envZ_ext_sandbox_instance_teardownZ_vi)(i0);
  i0 = l3;
  i0 = !(i0);
  if (i0) {goto B7;}
  i0 = l3;
  i1 = 2u;
  i0 <<= (i1 & 31);
  p0 = i0;
  i0 = l5;
  p1 = i0;
  L8: 
    i0 = p1;
    i0 = i32_load((&memory), (u64)(i0));
    l3 = i0;
    i1 = l3;
    i1 = i32_load((&memory), (u64)(i1));
    i2 = 4294967295u;
    i1 += i2;
    i32_store((&memory), (u64)(i0), i1);
    i0 = p1;
    i0 = i32_load((&memory), (u64)(i0));
    l3 = i0;
    i0 = i32_load((&memory), (u64)(i0));
    if (i0) {goto B10;}
    i0 = l3;
    i0 = i32_load((&memory), (u64)(i0 + 8));
    (*Z_envZ_ext_sandbox_memory_teardownZ_vi)(i0);
    i0 = p1;
    i0 = i32_load((&memory), (u64)(i0));
    l3 = i0;
    i1 = l3;
    i1 = i32_load((&memory), (u64)(i1 + 4));
    i2 = 4294967295u;
    i1 += i2;
    i32_store((&memory), (u64)(i0 + 4), i1);
    i0 = p1;
    i0 = i32_load((&memory), (u64)(i0));
    l3 = i0;
    i0 = i32_load((&memory), (u64)(i0 + 4));
    i0 = !(i0);
    if (i0) {goto B9;}
    B10:;
    i0 = p1;
    i1 = 4u;
    i0 += i1;
    p1 = i0;
    i0 = p0;
    i1 = 4294967292u;
    i0 += i1;
    p0 = i0;
    if (i0) {goto L8;}
    goto B7;
    B9:;
    i0 = l3;
    __rust_dealloc(i0);
    i0 = p1;
    i1 = 4u;
    i0 += i1;
    p1 = i0;
    i0 = p0;
    i1 = 4294967292u;
    i0 += i1;
    p0 = i0;
    if (i0) {goto L8;}
  B7:;
  i0 = 0u;
  p0 = i0;
  i0 = l4;
  i0 = !(i0);
  if (i0) {goto B11;}
  i0 = l5;
  __rust_dealloc(i0);
  B11:;
  i0 = 1u;
  l3 = i0;
  i0 = 1u;
  i0 = __rust_alloc(i0);
  p1 = i0;
  i0 = !(i0);
  if (i0) {goto B0;}
  goto B1;
  B3:;
  i0 = p0;
  __rust_dealloc(i0);
  B2:;
  i0 = 131841u;
  i1 = p1;
  i0 >>= (i1 & 31);
  p0 = i0;
  i0 = 1u;
  l3 = i0;
  i0 = 1u;
  i0 = __rust_alloc(i0);
  p1 = i0;
  i0 = !(i0);
  if (i0) {goto B0;}
  B1:;
  i0 = p1;
  i1 = p0;
  i32_store8((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = 64u;
  i0 += i1;
  g0 = i0;
  i0 = p1;
  j0 = (u64)(i0);
  j1 = 4294967296ull;
  j0 |= j1;
  goto Bfunc;
  B0:;
  i0 = l3;
  i1 = l3;
  rust_oom(i0, i1);
  UNREACHABLE;
  Bfunc:;
  FUNC_EPILOGUE;
  return j0;
}

static u64 _ZN10sr_sandbox3imp14dispatch_thunk17h4d4a64aa4b62dc7dE(u32 p0, u32 p1, u32 p2, u32 p3) {
  u32 l4 = 0;
  u64 l5 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3, i4;
  u64 j0, j1;
  i0 = g0;
  i1 = 32u;
  i0 -= i1;
  l4 = i0;
  g0 = i0;
  i0 = l4;
  i1 = p1;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l4;
  i1 = p0;
  i2 = 1049368u;
  i3 = p1;
  i1 = i3 ? i1 : i2;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l4;
  i1 = 16u;
  i0 += i1;
  i1 = l4;
  _ZN72__LT_alloc__vec__Vec_LT_T_GT__u20_as_u20_parity_codec__codec__Decode_GT_6decode17hc89f3b72474bfd56E(i0, i1);
  i0 = l4;
  i0 = i32_load((&memory), (u64)(i0 + 16));
  p1 = i0;
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = l4;
  i0 = i32_load((&memory), (u64)(i0 + 20));
  p0 = i0;
  i0 = l4;
  i1 = 16u;
  i0 += i1;
  i1 = p2;
  i2 = p1;
  i3 = l4;
  i4 = 24u;
  i3 += i4;
  i3 = i32_load((&memory), (u64)(i3));
  i4 = p3;
  CALL_INDIRECT(__indirect_function_table, void (*)(u32, u32, u32, u32), 2, i4, i0, i1, i2, i3);
  i0 = l4;
  i1 = l4;
  i2 = 16u;
  i1 += i2;
  _ZN12parity_codec5codec6Encode6encode17ha70755ab770d169bE(i0, i1);
  i0 = l4;
  j0 = i64_load32_u((&memory), (u64)(i0));
  j1 = 32ull;
  j0 <<= (j1 & 63);
  i1 = l4;
  j1 = i64_load32_u((&memory), (u64)(i1 + 8));
  j0 |= j1;
  l5 = j0;
  i0 = p0;
  i0 = !(i0);
  if (i0) {goto B1;}
  i0 = p1;
  __rust_dealloc(i0);
  B1:;
  i0 = l4;
  i1 = 32u;
  i0 += i1;
  g0 = i0;
  j0 = l5;
  goto Bfunc;
  B0:;
  _ZN4core6option13expect_failed17he3f99b0653a0c0b7E();
  UNREACHABLE;
  Bfunc:;
  FUNC_EPILOGUE;
  return j0;
}

static u32 memset_0(u32 p0, u32 p1, u32 p2) {
  u32 l3 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1;
  i0 = p2;
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = p0;
  l3 = i0;
  L1: 
    i0 = l3;
    i1 = p1;
    i32_store8((&memory), (u64)(i0), i1);
    i0 = l3;
    i1 = 1u;
    i0 += i1;
    l3 = i0;
    i0 = p2;
    i1 = 4294967295u;
    i0 += i1;
    p2 = i0;
    if (i0) {goto L1;}
  B0:;
  i0 = p0;
  FUNC_EPILOGUE;
  return i0;
}

static u32 memcpy_0(u32 p0, u32 p1, u32 p2) {
  u32 l3 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1;
  i0 = p2;
  i0 = !(i0);
  if (i0) {goto B0;}
  i0 = p0;
  l3 = i0;
  L1: 
    i0 = l3;
    i1 = p1;
    i1 = i32_load8_u((&memory), (u64)(i1));
    i32_store8((&memory), (u64)(i0), i1);
    i0 = l3;
    i1 = 1u;
    i0 += i1;
    l3 = i0;
    i0 = p1;
    i1 = 1u;
    i0 += i1;
    p1 = i0;
    i0 = p2;
    i1 = 4294967295u;
    i0 += i1;
    p2 = i0;
    if (i0) {goto L1;}
  B0:;
  i0 = p0;
  FUNC_EPILOGUE;
  return i0;
}

static const u8 data_segment_data_0[] = {
  0x52, 0x75, 0x6e, 0x74, 0x69, 0x6d, 0x65, 0x20, 0x6d, 0x65, 0x6d, 0x6f, 
  0x72, 0x79, 0x20, 0x65, 0x78, 0x68, 0x61, 0x75, 0x73, 0x74, 0x65, 0x64, 
  0x2e, 0x20, 0x41, 0x62, 0x6f, 0x72, 0x74, 0x69, 0x6e, 0x67, 0x63, 0x61, 
  0x70, 0x61, 0x63, 0x69, 0x74, 0x79, 0x20, 0x6f, 0x76, 0x65, 0x72, 0x66, 
  0x6c, 0x6f, 0x77, 0x73, 0x72, 0x63, 0x2f, 0x6c, 0x69, 0x62, 0x61, 0x6c, 
  0x6c, 0x6f, 0x63, 0x2f, 0x72, 0x61, 0x77, 0x5f, 0x76, 0x65, 0x63, 0x2e, 
  0x72, 0x73, 0x30, 0x30, 0x30, 0x31, 0x30, 0x32, 0x30, 0x33, 0x30, 0x34, 
  0x30, 0x35, 0x30, 0x36, 0x30, 0x37, 0x30, 0x38, 0x30, 0x39, 0x31, 0x30, 
  0x31, 0x31, 0x31, 0x32, 0x31, 0x33, 0x31, 0x34, 0x31, 0x35, 0x31, 0x36, 
  0x31, 0x37, 0x31, 0x38, 0x31, 0x39, 0x32, 0x30, 0x32, 0x31, 0x32, 0x32, 
  0x32, 0x33, 0x32, 0x34, 0x32, 0x35, 0x32, 0x36, 0x32, 0x37, 0x32, 0x38, 
  0x32, 0x39, 0x33, 0x30, 0x33, 0x31, 0x33, 0x32, 0x33, 0x33, 0x33, 0x34, 
  0x33, 0x35, 0x33, 0x36, 0x33, 0x37, 0x33, 0x38, 0x33, 0x39, 0x34, 0x30, 
  0x34, 0x31, 0x34, 0x32, 0x34, 0x33, 0x34, 0x34, 0x34, 0x35, 0x34, 0x36, 
  0x34, 0x37, 0x34, 0x38, 0x34, 0x39, 0x35, 0x30, 0x35, 0x31, 0x35, 0x32, 
  0x35, 0x33, 0x35, 0x34, 0x35, 0x35, 0x35, 0x36, 0x35, 0x37, 0x35, 0x38, 
  0x35, 0x39, 0x36, 0x30, 0x36, 0x31, 0x36, 0x32, 0x36, 0x33, 0x36, 0x34, 
  0x36, 0x35, 0x36, 0x36, 0x36, 0x37, 0x36, 0x38, 0x36, 0x39, 0x37, 0x30, 
  0x37, 0x31, 0x37, 0x32, 0x37, 0x33, 0x37, 0x34, 0x37, 0x35, 0x37, 0x36, 
  0x37, 0x37, 0x37, 0x38, 0x37, 0x39, 0x38, 0x30, 0x38, 0x31, 0x38, 0x32, 
  0x38, 0x33, 0x38, 0x34, 0x38, 0x35, 0x38, 0x36, 0x38, 0x37, 0x38, 0x38, 
  0x38, 0x39, 0x39, 0x30, 0x39, 0x31, 0x39, 0x32, 0x39, 0x33, 0x39, 0x34, 
  0x39, 0x35, 0x39, 0x36, 0x39, 0x37, 0x39, 0x38, 0x39, 0x39, 0x69, 0x6e, 
  0x64, 0x65, 0x78, 0x20, 0x20, 0x6f, 0x75, 0x74, 0x20, 0x6f, 0x66, 0x20, 
  0x72, 0x61, 0x6e, 0x67, 0x65, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x73, 0x6c, 
  0x69, 0x63, 0x65, 0x20, 0x6f, 0x66, 0x20, 0x6c, 0x65, 0x6e, 0x67, 0x74, 
  0x68, 0x20, 0x73, 0x6c, 0x69, 0x63, 0x65, 0x20, 0x69, 0x6e, 0x64, 0x65, 
  0x78, 0x20, 0x73, 0x74, 0x61, 0x72, 0x74, 0x73, 0x20, 0x61, 0x74, 0x20, 
  0x20, 0x62, 0x75, 0x74, 0x20, 0x65, 0x6e, 0x64, 0x73, 0x20, 0x61, 0x74, 
  0x20, 0x73, 0x72, 0x63, 0x2f, 0x6c, 0x69, 0x62, 0x63, 0x6f, 0x72, 0x65, 
  0x2f, 0x73, 0x6c, 0x69, 0x63, 0x65, 0x2f, 0x6d, 0x6f, 0x64, 0x2e, 0x72, 
  0x73, 0x73, 0x65, 0x74, 0x5f, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 
  0x69, 0x6e, 0x70, 0x75, 0x74, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 
  0x66, 0x6f, 0x6f, 0x62, 0x61, 0x7a, 0x66, 0x69, 0x6e, 0x69, 0x73, 0x68, 
  0x65, 0x64, 0x21, 0x61, 0x6c, 0x6c, 0x20, 0x6f, 0x6b, 0x21, 0x63, 0x61, 
  0x6c, 0x6c, 0x65, 0x64, 0x20, 0x60, 0x4f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 
  0x3a, 0x3a, 0x75, 0x6e, 0x77, 0x72, 0x61, 0x70, 0x28, 0x29, 0x60, 0x20, 
  0x6f, 0x6e, 0x20, 0x61, 0x20, 0x60, 0x4e, 0x6f, 0x6e, 0x65, 0x60, 0x20, 
  0x76, 0x61, 0x6c, 0x75, 0x65, 0x73, 0x72, 0x63, 0x2f, 0x6c, 0x69, 0x62, 
  0x63, 0x6f, 0x72, 0x65, 0x2f, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 
  0x72, 0x73, 0x74, 0x65, 0x73, 0x74, 0x20, 0x70, 0x61, 0x6e, 0x69, 0x63, 
  0x73, 0x72, 0x63, 0x2f, 0x6c, 0x69, 0x62, 0x2e, 0x72, 0x73, 0x7a, 0x65, 
  0x72, 0x6f, 0x6f, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x65, 0x6e, 0x76, 0x61, 
  0x73, 0x73, 0x65, 0x72, 0x74, 0x69, 0x6e, 0x63, 0x5f, 0x63, 0x6f, 0x75, 
  0x6e, 0x74, 0x65, 0x72, 0x63, 0x61, 0x6c, 0x6c, 0x6d, 0x65, 0x6d, 0x6f, 
  0x72, 0x79, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x20, 0x65, 
  0x72, 0x72, 0x6f, 0x72, 0x3a, 0x20, 0x65, 0x6e, 0x74, 0x65, 0x72, 0x65, 
  0x64, 0x20, 0x75, 0x6e, 0x72, 0x65, 0x61, 0x63, 0x68, 0x61, 0x62, 0x6c, 
  0x65, 0x20, 0x63, 0x6f, 0x64, 0x65, 0x3a, 0x20, 0x0a, 0x09, 0x09, 0x09, 
  0x09, 0x4d, 0x65, 0x6d, 0x6f, 0x72, 0x79, 0x3a, 0x3a, 0x6e, 0x65, 0x77, 
  0x28, 0x29, 0x20, 0x63, 0x61, 0x6e, 0x20, 0x72, 0x65, 0x74, 0x75, 0x72, 
  0x6e, 0x20, 0x45, 0x72, 0x72, 0x20, 0x6f, 0x6e, 0x6c, 0x79, 0x20, 0x69, 
  0x66, 0x20, 0x70, 0x61, 0x72, 0x61, 0x6d, 0x65, 0x74, 0x65, 0x72, 0x73, 
  0x20, 0x61, 0x72, 0x65, 0x20, 0x62, 0x6f, 0x72, 0x6b, 0x65, 0x64, 0x3b, 
  0x20, 0x57, 0x65, 0x20, 0x70, 0x61, 0x73, 0x73, 0x69, 0x6e, 0x67, 0x20, 
  0x70, 0x61, 0x72, 0x61, 0x6d, 0x73, 0x20, 0x68, 0x65, 0x72, 0x65, 0x20, 
  0x65, 0x78, 0x70, 0x6c, 0x69, 0x63, 0x69, 0x74, 0x6c, 0x79, 0x20, 0x61, 
  0x6e, 0x64, 0x20, 0x74, 0x68, 0x65, 0x79, 0x27, 0x72, 0x65, 0x20, 0x63, 
  0x6f, 0x72, 0x72, 0x65, 0x63, 0x74, 0x3b, 0x20, 0x4d, 0x65, 0x6d, 0x6f, 
  0x72, 0x79, 0x3a, 0x3a, 0x6e, 0x65, 0x77, 0x28, 0x29, 0x20, 0x63, 0x61, 
  0x6e, 0x27, 0x74, 0x20, 0x72, 0x65, 0x74, 0x75, 0x72, 0x6e, 0x20, 0x61, 
  0x20, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x20, 0x71, 0x65, 0x64, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x21, 0x43, 0x65, 0x87, 0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 
  0x36, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x73, 0x65, 0x72, 0x69, 0x61, 0x6c, 0x69, 0x7a, 0x65, 0x64, 0x20, 0x61, 
  0x72, 0x67, 0x73, 0x20, 0x73, 0x68, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x62, 
  0x65, 0x20, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x64, 0x20, 0x62, 
  0x79, 0x20, 0x74, 0x68, 0x65, 0x20, 0x72, 0x75, 0x6e, 0x74, 0x69, 0x6d, 
  0x65, 0x3b, 0x0a, 0x09, 0x09, 0x09, 0x63, 0x6f, 0x72, 0x72, 0x65, 0x63, 
  0x74, 0x6c, 0x79, 0x20, 0x73, 0x65, 0x72, 0x69, 0x61, 0x6c, 0x69, 0x7a, 
  0x65, 0x64, 0x20, 0x64, 0x61, 0x74, 0x61, 0x20, 0x73, 0x68, 0x6f, 0x75, 
  0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x64, 0x65, 0x73, 0x65, 0x72, 0x69, 
  0x61, 0x6c, 0x69, 0x7a, 0x61, 0x62, 0x6c, 0x65, 0x3b, 0x0a, 0x09, 0x09, 
  0x09, 0x71, 0x65, 0x64, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 
  0x20, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x3a, 0x20, 0x65, 0x6e, 0x74, 0x65, 
  0x72, 0x65, 0x64, 0x20, 0x75, 0x6e, 0x72, 0x65, 0x61, 0x63, 0x68, 0x61, 
  0x62, 0x6c, 0x65, 0x20, 0x63, 0x6f, 0x64, 0x65, 0x2f, 0x68, 0x6f, 0x6d, 
  0x65, 0x2f, 0x6d, 0x69, 0x63, 0x68, 0x69, 0x2f, 0x70, 0x72, 0x6f, 0x6a, 
  0x65, 0x63, 0x74, 0x73, 0x2f, 0x73, 0x75, 0x62, 0x73, 0x74, 0x72, 0x61, 
  0x74, 0x65, 0x2f, 0x63, 0x6f, 0x72, 0x65, 0x2f, 0x73, 0x72, 0x2d, 0x73, 
  0x61, 0x6e, 0x64, 0x62, 0x6f, 0x78, 0x2f, 0x73, 0x72, 0x63, 0x2f, 0x2e, 
  0x2e, 0x2f, 0x77, 0x69, 0x74, 0x68, 0x6f, 0x75, 0x74, 0x5f, 0x73, 0x74, 
  0x64, 0x2e, 0x72, 0x73, 
};

static const u8 data_segment_data_1[] = {
  0x22, 0x00, 0x10, 0x00, 0x11, 0x00, 0x00, 0x00, 0x33, 0x00, 0x10, 0x00, 
  0x17, 0x00, 0x00, 0x00, 0xeb, 0x02, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 
  0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 
  0x08, 0x00, 0x00, 0x00, 0x12, 0x01, 0x10, 0x00, 0x06, 0x00, 0x00, 0x00, 
  0x18, 0x01, 0x10, 0x00, 0x22, 0x00, 0x00, 0x00, 0x5d, 0x01, 0x10, 0x00, 
  0x18, 0x00, 0x00, 0x00, 0x6a, 0x09, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 
  0x3a, 0x01, 0x10, 0x00, 0x16, 0x00, 0x00, 0x00, 0x50, 0x01, 0x10, 0x00, 
  0x0d, 0x00, 0x00, 0x00, 0x5d, 0x01, 0x10, 0x00, 0x18, 0x00, 0x00, 0x00, 
  0x70, 0x09, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x18, 0x03, 0x10, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0xcd, 0x01, 0x10, 0x00, 0x15, 0x00, 0x00, 0x00, 
  0x0e, 0x04, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0xa2, 0x01, 0x10, 0x00, 
  0x2b, 0x00, 0x00, 0x00, 0xcd, 0x01, 0x10, 0x00, 0x15, 0x00, 0x00, 0x00, 
  0x59, 0x01, 0x00, 0x00, 0x15, 0x00, 0x00, 0x00, 0xe2, 0x01, 0x10, 0x00, 
  0x0a, 0x00, 0x00, 0x00, 0xec, 0x01, 0x10, 0x00, 0x0a, 0x00, 0x00, 0x00, 
  0x3e, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0xe2, 0x01, 0x10, 0x00, 
  0x0a, 0x00, 0x00, 0x00, 0xec, 0x01, 0x10, 0x00, 0x0a, 0x00, 0x00, 0x00, 
  0x41, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x48, 0x02, 0x10, 0x00, 
  0x9e, 0x00, 0x00, 0x00, 0x1e, 0x02, 0x10, 0x00, 0x2a, 0x00, 0x00, 0x00, 
  0xec, 0x01, 0x10, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x9a, 0x00, 0x00, 0x00, 
  0x0e, 0x00, 0x00, 0x00, 0x88, 0x03, 0x10, 0x00, 0x28, 0x00, 0x00, 0x00, 
  0xb0, 0x03, 0x10, 0x00, 0x44, 0x00, 0x00, 0x00, 0x37, 0x01, 0x00, 0x00, 
  0x09, 0x00, 0x00, 0x00, 
};

static void init_memory(void) {
  wasm_rt_allocate_memory((&memory), 17, 65536);
  memcpy(&(memory.data[1048576u]), data_segment_data_0, 1012);
  memcpy(&(memory.data[1049588u]), data_segment_data_1, 256);
}

static void init_table(void) {
  uint32_t offset;
  wasm_rt_allocate_table((&__indirect_function_table), 9, 9);
  offset = 1u;
  __indirect_function_table.data[offset + 0] = (wasm_rt_elem_t){func_types[0], (wasm_rt_anyfunc_t)(&_ZN4core3fmt3num52__LT_impl_u20_core__fmt__Display_u20_for_u20_u32_GT_3fmt17h3f2435e6f3e4ac83E)};
  __indirect_function_table.data[offset + 1] = (wasm_rt_elem_t){func_types[0], (wasm_rt_anyfunc_t)(&_ZN44__LT__RF_T_u20_as_u20_core__fmt__Display_GT_3fmt17h01b6108549776650E)};
  __indirect_function_table.data[offset + 2] = (wasm_rt_elem_t){func_types[2], (wasm_rt_anyfunc_t)(&_ZN12runtime_test17execute_sandboxed10env_assert17h1a8e102f17474114E)};
  __indirect_function_table.data[offset + 3] = (wasm_rt_elem_t){func_types[2], (wasm_rt_anyfunc_t)(&_ZN12runtime_test17execute_sandboxed15env_inc_counter17h43632cbfffd814eeE)};
  __indirect_function_table.data[offset + 4] = (wasm_rt_elem_t){func_types[17], (wasm_rt_anyfunc_t)(&_ZN10sr_sandbox3imp14dispatch_thunk17hd12b2ae46f5bc54cE)};
  __indirect_function_table.data[offset + 5] = (wasm_rt_elem_t){func_types[17], (wasm_rt_anyfunc_t)(&_ZN10sr_sandbox3imp14dispatch_thunk17h4d4a64aa4b62dc7dE)};
  __indirect_function_table.data[offset + 6] = (wasm_rt_elem_t){func_types[6], (wasm_rt_anyfunc_t)(&_ZN4core3ptr18real_drop_in_place17h73c609b348f6cf67E)};
  __indirect_function_table.data[offset + 7] = (wasm_rt_elem_t){func_types[13], (wasm_rt_anyfunc_t)(&_ZN36__LT_T_u20_as_u20_core__any__Any_GT_11get_type_id17h1457de5e51092096E)};
}

/* export: 'memory' */
wasm_rt_memory_t (*WASM_RT_ADD_PREFIX(Z_memory));
/* export: '__indirect_function_table' */
wasm_rt_table_t (*WASM_RT_ADD_PREFIX(Z___indirect_function_table));
/* export: '__heap_base' */
u32 (*WASM_RT_ADD_PREFIX(Z___heap_baseZ_i));
/* export: '__data_end' */
u32 (*WASM_RT_ADD_PREFIX(Z___data_endZ_i));
/* export: 'test_data_in' */
u64 (*WASM_RT_ADD_PREFIX(Z_test_data_inZ_jii))(u32, u32);
/* export: 'test_clear_prefix' */
u64 (*WASM_RT_ADD_PREFIX(Z_test_clear_prefixZ_jii))(u32, u32);
/* export: 'test_empty_return' */
u64 (*WASM_RT_ADD_PREFIX(Z_test_empty_returnZ_jii))(u32, u32);
/* export: 'test_panic' */
u64 (*WASM_RT_ADD_PREFIX(Z_test_panicZ_jii))(u32, u32);
/* export: 'test_conditional_panic' */
u64 (*WASM_RT_ADD_PREFIX(Z_test_conditional_panicZ_jii))(u32, u32);
/* export: 'test_blake2_256' */
u64 (*WASM_RT_ADD_PREFIX(Z_test_blake2_256Z_jii))(u32, u32);
/* export: 'test_twox_256' */
u64 (*WASM_RT_ADD_PREFIX(Z_test_twox_256Z_jii))(u32, u32);
/* export: 'test_twox_128' */
u64 (*WASM_RT_ADD_PREFIX(Z_test_twox_128Z_jii))(u32, u32);
/* export: 'test_ed25519_verify' */
u64 (*WASM_RT_ADD_PREFIX(Z_test_ed25519_verifyZ_jii))(u32, u32);
/* export: 'test_enumerated_trie_root' */
u64 (*WASM_RT_ADD_PREFIX(Z_test_enumerated_trie_rootZ_jii))(u32, u32);
/* export: 'test_sandbox' */
u64 (*WASM_RT_ADD_PREFIX(Z_test_sandboxZ_jii))(u32, u32);
/* export: 'test_sandbox_args' */
u64 (*WASM_RT_ADD_PREFIX(Z_test_sandbox_argsZ_jii))(u32, u32);
/* export: 'test_sandbox_return_val' */
u64 (*WASM_RT_ADD_PREFIX(Z_test_sandbox_return_valZ_jii))(u32, u32);
/* export: 'test_sandbox_instantiate' */
u64 (*WASM_RT_ADD_PREFIX(Z_test_sandbox_instantiateZ_jii))(u32, u32);

static void init_exports(void) {
  fprintf(stderr, "init_exports");
  /* export: 'memory' */
  WASM_RT_ADD_PREFIX(Z_memory) = (&memory);
  /* export: '__indirect_function_table' */
  WASM_RT_ADD_PREFIX(Z___indirect_function_table) = (&__indirect_function_table);
  /* export: '__heap_base' */
  WASM_RT_ADD_PREFIX(Z___heap_baseZ_i) = (&__heap_base);
  /* export: '__data_end' */
  WASM_RT_ADD_PREFIX(Z___data_endZ_i) = (&__data_end);
  /* export: 'test_data_in' */
  WASM_RT_ADD_PREFIX(Z_test_data_inZ_jii) = (&test_data_in);
  /* export: 'test_clear_prefix' */
  WASM_RT_ADD_PREFIX(Z_test_clear_prefixZ_jii) = (&test_clear_prefix);

  /* export: 'test_empty_return' */

  WASM_RT_ADD_PREFIX(Z_test_empty_returnZ_jii) = (&test_empty_return);
  fprintf(stderr, "pointer p %p\n", &test_empty_return);
  fprintf(stderr, "pointer x %x\n", &test_empty_return);

  fprintf(stderr, "pointer2 p %p\n", &Z_test_empty_returnZ_jii);
  fprintf(stderr, "pointer2 x %x\n", &Z_test_empty_returnZ_jii);

  //WASM_RT_ADD_PREFIX(Z_test_empty_returnZ_jii) = (&test_empty_return);

  /* export: 'test_panic' */
  WASM_RT_ADD_PREFIX(Z_test_panicZ_jii) = (&test_panic);
  /* export: 'test_conditional_panic' */
  WASM_RT_ADD_PREFIX(Z_test_conditional_panicZ_jii) = (&test_conditional_panic);
  /* export: 'test_blake2_256' */
  WASM_RT_ADD_PREFIX(Z_test_blake2_256Z_jii) = (&test_blake2_256);
  /* export: 'test_twox_256' */
  WASM_RT_ADD_PREFIX(Z_test_twox_256Z_jii) = (&test_twox_256);
  /* export: 'test_twox_128' */
  WASM_RT_ADD_PREFIX(Z_test_twox_128Z_jii) = (&test_twox_128);
  /* export: 'test_ed25519_verify' */
  WASM_RT_ADD_PREFIX(Z_test_ed25519_verifyZ_jii) = (&test_ed25519_verify);
  /* export: 'test_enumerated_trie_root' */
  WASM_RT_ADD_PREFIX(Z_test_enumerated_trie_rootZ_jii) = (&test_enumerated_trie_root);
  /* export: 'test_sandbox' */
  WASM_RT_ADD_PREFIX(Z_test_sandboxZ_jii) = (&test_sandbox);
  /* export: 'test_sandbox_args' */
  WASM_RT_ADD_PREFIX(Z_test_sandbox_argsZ_jii) = (&test_sandbox_args);
  /* export: 'test_sandbox_return_val' */
  WASM_RT_ADD_PREFIX(Z_test_sandbox_return_valZ_jii) = (&test_sandbox_return_val);
  /* export: 'test_sandbox_instantiate' */
  WASM_RT_ADD_PREFIX(Z_test_sandbox_instantiateZ_jii) = (&test_sandbox_instantiate);
}

void WASM_RT_ADD_PREFIX(init)(void) {
  fprintf(stderr, "init_func_types\n");
  init_func_types();

  fprintf(stderr, "init_globals\n");
  init_globals();

  fprintf(stderr, "init_memory\n");
  init_memory();

  fprintf(stderr, "init_table\n");
  init_table();

  fprintf(stderr, "init_exports\n");
  init_exports();
}
