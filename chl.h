#ifndef CHL_H
#define CHL_H

#include <stdio.h>
#include <stdint.h>

#define CHLPP_IF0(...)
#define CHLPP_IF1(...) __VA_ARGS__
#define CHLPP_IFc(c, ...) CHLPP_IF ## c(__VA_ARGS__)
#define CHLPP_IF(c, ...) CHLPP_IFc(c, __VA_ARGS__)

typedef struct chl_array_128b_t {
    uint8_t array[16];
} chl_array_128b_t;

/* DO:
 * name of function
 * return type
 */

#define CHL_LIST_OF_NAMES \
DO(djb2,     uint32_t) \
DO(pjw32,    uint32_t) \
DO(pjw64,    uint64_t) \
DO(fnv1_32,  uint32_t) \
DO(fnv1a_32, uint32_t) \
DO(fnv1_64,  uint64_t) \
DO(fnv1a_64, uint64_t) \
DO(crc32b,   uint32_t) \
DO(crc32c,   uint32_t) \

/* DO:
 * name of function
 * return type
 * key type
 * key name
 */

#define CHL_LIST_OF_NAMES_WITH_KEY \
DO(siphash_2_4, uint64_t, chl_array_128b_t, le_key) \

#define CHLN_RET_T(bn)    chl_ ## bn ## _ret_t
#define CHLN_FUNC(bn, fn) chl_ ## bn ## _ ## fn

#ifdef __cplusplus
extern "C" {
#endif

// Return type
#define DO(name, ret) \
typedef ret CHLN_RET_T(name);
CHL_LIST_OF_NAMES
#undef DO

// Calculations functions
#define DO(name, ret) \
ret CHLN_FUNC(name, calc)(const void* source, size_t length); \
ret CHLN_FUNC(name, calc_file)(FILE* src_file);
CHL_LIST_OF_NAMES
#undef DO

// Return type
#define DO(name, ret, ...) \
typedef ret CHLN_RET_T(name);
CHL_LIST_OF_NAMES_WITH_KEY
#undef DO

// Calculations functions with key
#define DO(name, ret, ktype, kname) \
ret CHLN_FUNC(name, calc)(const void* source, size_t length, ktype kname); \
ret CHLN_FUNC(name, calc_file)(FILE* src_file, ktype kname);
CHL_LIST_OF_NAMES_WITH_KEY
#undef DO

#ifdef __cplusplus
}
#endif

#ifndef CHL_DFLT
#define CHL_DFLT djb2
#endif

#define CHLN_RET_T_EXP(bn)    CHLN_RET_T(bn)
#define CHLN_FUNC_EXP(bn, fn) CHLN_FUNC(bn, fn)

#define chl_ret_t     CHLN_RET_T_EXP(CHL_DFLT)
#define chl_calc      CHLN_FUNC_EXP(CHL_DFLT, calc)
#define chl_calc_file CHLN_FUNC_EXP(CHL_DFLT, calc_file)

#endif // CHL_H