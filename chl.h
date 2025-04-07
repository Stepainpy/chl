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

#define CHL_LIST_OF_BITS \
DO(128) DO(160) DO(224)  \
DO(256) DO(384) DO(512)  \
DO(1024)

#define CHL_BITS_NAME(bits) chl_ ## bits ## bit_t

#define DO(b) \
typedef struct { \
    uint8_t array[b/8]; \
} CHL_BITS_NAME(b);
CHL_LIST_OF_BITS
#undef DO

typedef struct {
    const void* data;
    size_t count;
} chl_byte_span_t;

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
DO(ripemd_160,   chl_160bit_t) \

/* DO:
 * name of function
 * return type
 * key type
 * key name
 */

#define CHL_LIST_OF_NAMES_WITH_KEY \
DO(siphash_2_4,   uint64_t,     chl_128bit_t, le_key) \
DO(hmac_md5,      chl_128bit_t, chl_byte_span_t, key) \
DO(hmac_sha1,     chl_160bit_t, chl_byte_span_t, key) \
DO(hmac_sha2_224, chl_224bit_t, chl_byte_span_t, key) \
DO(hmac_sha2_256, chl_256bit_t, chl_byte_span_t, key) \
DO(hmac_sha2_384, chl_384bit_t, chl_byte_span_t, key) \
DO(hmac_sha2_512, chl_512bit_t, chl_byte_span_t, key) \

#define CHLN_RET_T(bn)    chl_ ## bn ## _ret_t
#define CHLN_KEY_T(bn)    chl_ ## bn ## _key_t
#define CHLN_FUNC(bn, fn) chl_ ## bn ## _ ## fn

#ifdef __cplusplus
extern "C" {
#endif

// Text only
#define DO(name, ret) \
typedef ret CHLN_RET_T(name); \
ret CHLN_FUNC(name, calc_span)(const void* source, size_t length); \
ret CHLN_FUNC(name, calc_file)(FILE* src_file);
CHL_LIST_OF_NAMES
#undef DO

// Text and key
#define DO(name, ret, ktype, kname) \
typedef ret   CHLN_RET_T(name); \
typedef ktype CHLN_KEY_T(name); \
ret CHLN_FUNC(name, calc_span)(const void* source, size_t length, ktype kname); \
ret CHLN_FUNC(name, calc_file)(FILE* src_file, ktype kname);
CHL_LIST_OF_NAMES_WITH_KEY
#undef DO

#ifdef __cplusplus
}
#endif

#ifndef CHL_DEFAULT
#define CHL_DEFAULT djb2
#endif

#define CHLN_RET_T_EXP(bn)    CHLN_RET_T(bn)
#define CHLN_KEY_T_EXP(bn)    CHLN_KEY_T(bn)
#define CHLN_FUNC_EXP(bn, fn) CHLN_FUNC(bn, fn)

#define chl_ret_t     CHLN_RET_T_EXP(CHL_DEFAULT)
#define chl_key_t     CHLN_KEY_T_EXP(CHL_DEFAULT)
#define chl_calc_span CHLN_FUNC_EXP(CHL_DEFAULT, calc_span)
#define chl_calc_file CHLN_FUNC_EXP(CHL_DEFAULT, calc_file)

#endif // CHL_H