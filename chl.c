#include "chl.h"
#include <stdbool.h>
#include <string.h>

/* Definind stream */

typedef struct stm_t {
    union { const uint8_t* data; FILE* file; } ptr;
    size_t count; // if count == SIZE_MAX => ptr is file, otherwise is slice
} stm_t;

#define stm_def_from_file(fd)   (stm_t){ .count = SIZE_MAX, .ptr.file = fd }
#define stm_def_from_span(p, l) (stm_t){ .count = l,        .ptr.data = p  }
#define stm_is_file(stmp) ((stmp)->count == SIZE_MAX)

static int fpeek(FILE* file) {
    const int c = getc(file);
    return c == EOF ? EOF : ungetc(c, file);
}

static bool stm_has(stm_t* stm) {
    if (stm_is_file(stm))
        return fpeek(stm->ptr.file) != EOF;
    return stm->count > 0;
}

static uint8_t stm_read_byte(stm_t* stm) {
    if (stm_is_file(stm))
        return getc(stm->ptr.file);
    return (--stm->count, *stm->ptr.data++);
}

static size_t stm_read_block(stm_t* stm, void* dest, size_t count) {
    if (stm_is_file(stm))
        return fread(dest, 1, count, stm->ptr.file);

    const size_t min_len = count < stm->count
                         ? count : stm->count;
    memcpy(dest, stm->ptr.data, min_len);
    stm->ptr.data += min_len;
    stm->count    -= min_len;
    return min_len;
}

/* Byte order correction */

static inline uint32_t rev_bytes_32(uint32_t x) {
    x = (x & 0xffff0000) >> 16 | (x & 0x0000ffff) << 16;
    x = (x & 0xff00ff00) >>  8 | (x & 0x00ff00ff) <<  8;
    return x;
}

static inline uint64_t rev_bytes_64(uint64_t x) {
    x = (x & 0xffffffff00000000) >> 32 | (x & 0x00000000ffffffff) << 32;
    x = (x & 0xffff0000ffff0000) >> 16 | (x & 0x0000ffff0000ffff) << 16;
    x = (x & 0xff00ff00ff00ff00) >>  8 | (x & 0x00ff00ff00ff00ff) <<  8;
    return x;
}

#ifdef __BYTE_ORDER__
#  if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#    define le32(x) ((uint32_t)(x))
#    define le64(x) ((uint64_t)(x))
#    define be32(x) rev_bytes_32(x)
#    define be64(x) rev_bytes_64(x)
#  elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#    define le32(x) rev_bytes_32(x)
#    define le64(x) rev_bytes_64(x)
#    define be32(x) ((uint32_t)(x))
#    define be64(x) ((uint64_t)(x))
#  endif
#else
#  define le32(x) ((uint32_t)(x))
#  define le64(x) ((uint64_t)(x))
#  define be32(x) ((uint32_t)(x))
#  define be64(x) ((uint64_t)(x))
#endif

/* Bit rotations */

static inline uint32_t rotl32(uint32_t n, int s) { return n << s | n >> (32 - s); }
static inline uint32_t rotr32(uint32_t n, int s) { return n >> s | n << (32 - s); }
static inline uint64_t rotl64(uint64_t n, int s) { return n << s | n >> (64 - s); }
static inline uint64_t rotr64(uint64_t n, int s) { return n >> s | n << (64 - s); }

/* Defining `calc` and `calc_file` as versions of `base` */

#define DO(name, ret, hasext, etype, ename) \
static ret CHLN_FUNC(name, base)(stm_t stm \
    CHLPP_IF(hasext, CHLPP_COMMA) etype ename); \
ret CHLN_FUNC(name, calc)(const void* source, size_t length \
    CHLPP_IF(hasext, CHLPP_COMMA) etype ename) { \
    return CHLN_FUNC(name, base)(stm_def_from_span(source, length) \
        CHLPP_IF(hasext, CHLPP_COMMA) ename); \
} \
ret CHLN_FUNC(name, calc_file)(FILE* src_file \
    CHLPP_IF(hasext, CHLPP_COMMA) etype ename) { \
    return CHLN_FUNC(name, base)(stm_def_from_file(src_file) \
        CHLPP_IF(hasext, CHLPP_COMMA) ename); \
}
CHL_LIST_OF_NAMES
#undef DO

chl_djb2_ret_t chl_djb2_base(stm_t stm) {
    chl_djb2_ret_t hash = 5381;
    while (stm_has(&stm))
        hash = ((hash << 5) + hash) + stm_read_byte(&stm);
    return hash;
}

chl_pjw32_ret_t chl_pjw32_base(stm_t stm) {
    chl_pjw32_ret_t hash = 0, high;
    while (stm_has(&stm)) {
        hash = (hash << 4) + stm_read_byte(&stm);
        if ((high = hash & 0xf0000000)) {
            hash ^= high >> 24;
            hash &= ~high;
        }
    }
    return hash;
}

chl_pjw64_ret_t chl_pjw64_base(stm_t stm) {
    chl_pjw64_ret_t hash = 0, high;
    while (stm_has(&stm)) {
        hash = (hash << 8) + stm_read_byte(&stm);
        if ((high = hash & 0xff00000000000000)) {
            hash ^= high >> 48;
            hash &= ~high;
        }
    }
    return hash;
}

chl_fnv1_32_ret_t chl_fnv1_32_base(stm_t stm) {
    chl_fnv1_32_ret_t hash = 2166136261;
    while (stm_has(&stm)) {
        hash *= 16777619;
        hash ^= stm_read_byte(&stm);
    }
    return hash;
}

chl_fnv1a_32_ret_t chl_fnv1a_32_base(stm_t stm) {
    chl_fnv1a_32_ret_t hash = 2166136261;
    while (stm_has(&stm)) {
        hash ^= stm_read_byte(&stm);
        hash *= 16777619;
    }
    return hash;
}

chl_fnv1_64_ret_t chl_fnv1_64_base(stm_t stm) {
    chl_fnv1_64_ret_t hash = UINT64_C(14695981039346656037);
    while (stm_has(&stm)) {
        hash *= 1099511628211;
        hash ^= stm_read_byte(&stm);
    }
    return hash;
}

chl_fnv1a_64_ret_t chl_fnv1a_64_base(stm_t stm) {
    chl_fnv1a_64_ret_t hash = UINT64_C(14695981039346656037);
    while (stm_has(&stm)) {
        hash ^= stm_read_byte(&stm);
        hash *= 1099511628211;
    }
    return hash;
}

static void siphash_2_4_round(uint64_t* vs) {
    vs[0] += vs[1]; vs[2] += vs[3];
    vs[1]  = rotl64(vs[1], 13);
    vs[3]  = rotl64(vs[3], 16);
    vs[1] ^= vs[0]; vs[3] ^= vs[2];
    vs[0]  = rotl64(vs[0], 32);

    vs[2] += vs[1]; vs[0] += vs[3];
    vs[1]  = rotl64(vs[1], 17);
    vs[3]  = rotl64(vs[3], 21);
    vs[1] ^= vs[2]; vs[3] ^= vs[0];
    vs[2]  = rotl64(vs[2], 32);
}

chl_siphash_2_4_ret_t chl_siphash_2_4_base(stm_t stm, chl_array_128b_t key) {
    uint64_t* keypair = (uint64_t*)&(key.array);
    keypair[0] = le64(keypair[0]);
    keypair[1] = le64(keypair[1]);
    
    uint64_t vs[4] = {
        keypair[0] ^ 0x736f6d6570736575,
        keypair[1] ^ 0x646f72616e646f6d,
        keypair[0] ^ 0x6c7967656e657261,
        keypair[1] ^ 0x7465646279746573
    };

    bool has_next_block = true;
    size_t all_len = 0, read_len;
    while (stm_has(&stm) || has_next_block) {
        uint64_t mi = 0;
        all_len += (read_len =
            stm_read_block(&stm, &mi, sizeof mi)
        ); mi = le64(mi);

        if (read_len < 8) {
            mi |= ((uint64_t)all_len & 255) << 56;
            has_next_block = false;
        }

        vs[3] ^= mi;
        siphash_2_4_round(vs);
        siphash_2_4_round(vs);
        vs[0] ^= mi;
    }

    vs[2] ^= 255;
    siphash_2_4_round(vs);
    siphash_2_4_round(vs);
    siphash_2_4_round(vs);
    siphash_2_4_round(vs);

    return le64(vs[0] ^ vs[1] ^ vs[2] ^ vs[3]);
}