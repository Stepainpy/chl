#ifndef CHL_H
#define CHL_H

#include <stdio.h>
#include <stdint.h>

/* Hash storage semantic:
 * if result hash less or equal than 64 bit
 *   then hash is integer
 * else hash from online equal "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"
 *   then hash is array = { 0x2f, 0xd4, 0xe1, ..., 0x93, 0xeb, 0x12 }
 */

#define DO(b) \
typedef struct { \
    uint8_t array[b/8]; \
} chl_ ## b ## bit_t;
DO(128) DO(160) DO(224) \
DO(256) DO(384) DO(512)
#undef DO

/* DO:
 * name of function
 * return type
 */

#define CHL_LIST_OF_NAMES \
DO(djb2,         uint32_t) \
DO(pjw32,        uint32_t) \
DO(pjw64,        uint64_t) \
DO(fnv1_32,      uint32_t) \
DO(fnv1a_32,     uint32_t) \
DO(fnv1_64,      uint64_t) \
DO(fnv1a_64,     uint64_t) \
DO(crc32b,       uint32_t) \
DO(crc32c,       uint32_t) \
DO(jenkins,      uint32_t) \
DO(md5,          chl_128bit_t) \
DO(gost, /*WIP*/ chl_256bit_t) \
DO(sha1,         chl_160bit_t) \
DO(sha2_224,     chl_224bit_t) \
DO(sha2_256,     chl_256bit_t) \
DO(sha2_384,     chl_384bit_t) \
DO(sha2_512,     chl_512bit_t) \
DO(sha2_512_224, chl_224bit_t) \
DO(sha2_512_256, chl_256bit_t) \

/* DO:
 * name of function
 * return type
 * key type
 * key name
 */

#define CHL_LIST_OF_NAMES_WITH_KEY \
DO(siphash_2_4,   uint64_t,     chl_128bit_t, le_key) \
DO(hmac_sha2_256, chl_256bit_t, chl_512bit_t,    key) \

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