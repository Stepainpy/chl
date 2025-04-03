#include "chl.h"
#include <stdbool.h>
#include <string.h>
#include "tables.h"

/* Definind stream */

typedef struct stm_t {
    union { const uint8_t* data; FILE* file; } ptr;
    size_t count; // if count == SIZE_MAX then ptr is file, otherwise is span
} stm_t;

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

#define apply_to(arr, size, op) \
for (size_t macroi = 0; macroi < size; macroi++) \
    (arr)[macroi] = op((arr)[macroi])

/* Bit rotations */

static inline uint32_t rotl32(uint32_t n, int s) { return n << s | n >> (32 - s); }
static inline uint32_t rotr32(uint32_t n, int s) { return n >> s | n << (32 - s); }
static inline uint64_t rotl64(uint64_t n, int s) { return n << s | n >> (64 - s); }
static inline uint64_t rotr64(uint64_t n, int s) { return n >> s | n << (64 - s); }

/* Defining `calc` and `calc_file` as versions of `base` */

#define DO(name, ret) \
static ret CHLN_FUNC(name, base)(stm_t* stm); \
ret CHLN_FUNC(name, calc)(const void* source, size_t length) { \
    stm_t stm; stm.ptr.data = source; stm.count = length; \
    return CHLN_FUNC(name, base)(&stm); \
} \
ret CHLN_FUNC(name, calc_file)(FILE* src_file) { \
    stm_t stm; stm.ptr.file = src_file; stm.count = SIZE_MAX; \
    return CHLN_FUNC(name, base)(&stm); \
}
CHL_LIST_OF_NAMES
#undef DO

#define DO(name, ret, ktype, kname) \
static ret CHLN_FUNC(name, base)(stm_t* stm, ktype kname); \
ret CHLN_FUNC(name, calc)(const void* source, size_t length, ktype kname) { \
    stm_t stm; stm.ptr.data = source; stm.count = length; \
    return CHLN_FUNC(name, base)(&stm, kname); \
} \
ret CHLN_FUNC(name, calc_file)(FILE* src_file, ktype kname) { \
    stm_t stm; stm.ptr.file = src_file; stm.count = SIZE_MAX; \
    return CHLN_FUNC(name, base)(&stm, kname); \
}
CHL_LIST_OF_NAMES_WITH_KEY
#undef DO

chl_djb2_ret_t chl_djb2_base(stm_t* stm) {
    chl_djb2_ret_t hash = 5381;
    while (stm_has(stm))
        hash = ((hash << 5) + hash) + stm_read_byte(stm);
    return hash;
}

chl_pjw32_ret_t chl_pjw32_base(stm_t* stm) {
    chl_pjw32_ret_t hash = 0, high;
    while (stm_has(stm)) {
        hash = (hash << 4) + stm_read_byte(stm);
        if ((high = hash & 0xf0000000)) {
            hash ^= high >> 24;
            hash &= ~high;
        }
    }
    return hash;
}

chl_pjw64_ret_t chl_pjw64_base(stm_t* stm) {
    chl_pjw64_ret_t hash = 0, high;
    while (stm_has(stm)) {
        hash = (hash << 8) + stm_read_byte(stm);
        if ((high = hash & 0xff00000000000000)) {
            hash ^= high >> 48;
            hash &= ~high;
        }
    }
    return hash;
}

chl_fnv1_32_ret_t chl_fnv1_32_base(stm_t* stm) {
    chl_fnv1_32_ret_t hash = 2166136261;
    while (stm_has(stm)) {
        hash *= 16777619;
        hash ^= stm_read_byte(stm);
    }
    return hash;
}

chl_fnv1a_32_ret_t chl_fnv1a_32_base(stm_t* stm) {
    chl_fnv1a_32_ret_t hash = 2166136261;
    while (stm_has(stm)) {
        hash ^= stm_read_byte(stm);
        hash *= 16777619;
    }
    return hash;
}

chl_fnv1_64_ret_t chl_fnv1_64_base(stm_t* stm) {
    chl_fnv1_64_ret_t hash = UINT64_C(14695981039346656037);
    while (stm_has(stm)) {
        hash *= 1099511628211;
        hash ^= stm_read_byte(stm);
    }
    return hash;
}

chl_fnv1a_64_ret_t chl_fnv1a_64_base(stm_t* stm) {
    chl_fnv1a_64_ret_t hash = UINT64_C(14695981039346656037);
    while (stm_has(stm)) {
        hash ^= stm_read_byte(stm);
        hash *= 1099511628211;
    }
    return hash;
}

chl_crc32b_ret_t chl_crc32b_base(stm_t* stm) {
    chl_crc32b_ret_t hash = -1;
    while (stm_has(stm))
        hash = (hash >> 8) ^ crc32b_table[(hash ^ stm_read_byte(stm)) & 255];
    return ~hash;
}

chl_crc32c_ret_t chl_crc32c_base(stm_t* stm) {
    chl_crc32c_ret_t hash = -1;
    while (stm_has(stm))
        hash = (hash >> 8) ^ crc32c_table[(hash ^ stm_read_byte(stm)) & 255];
    return ~hash;
}

chl_sha1_ret_t chl_sha1_base(stm_t* stm) {
    uint32_t hs[5] = {
        0x67452301, 0xEFCDAB89, 0x98BADCFE,
        0x10325476, 0xC3D2E1F0
    };

    bool has_next_block     = true;
    bool need_paste_one_bit = true;
    size_t all_len = 0, read_len;
    while (stm_has(stm) || has_next_block) {
        uint32_t w[80] = {0};
        all_len += (read_len = stm_read_block(stm, w, 64));

        if (read_len < 64 && need_paste_one_bit) {
            *((uint8_t*)w + read_len) = 128;
            need_paste_one_bit = false;
        }
        if (read_len < 56) {
            *((uint64_t*)w + 7) = be64(all_len * 8);
            has_next_block = false;
        }

        apply_to(w, 16, be32);
        for (size_t i = 16; i < 80; i++)
            w[i] = rotl32(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);

        uint32_t a = hs[0], b = hs[1], c = hs[2], d = hs[3], e = hs[4];
        for (size_t i = 0; i < 80; i++) {
            uint32_t f, k;
            if (i < 20) {
                k = 0x5A827999; f = (b & c) | (~b & d);
            } else if (20 <= i && i < 40) {
                k = 0x6ED9EBA1; f = b ^ c ^ d;
            } else if (40 <= i && i < 60) {
                k = 0x8F1BBCDC; f = (b & c) ^ (b & d) ^ (c & d);
            } else {
                k = 0xCA62C1D6; f = b ^ c ^ d;
            }

            uint32_t t = rotl32(a, 5) + f + e + k + w[i];
            e = d; d = c; c = rotl32(b, 30); b = a; a = t;
        }
        hs[0] += a, hs[1] += b, hs[2] += c, hs[3] += d, hs[4] += e;
    }

    apply_to(hs, 5, be32);
    chl_sha1_ret_t hash = {0};
    memcpy(hash.array, hs, sizeof hs);
    return hash;
}

chl_sha2_224_ret_t chl_sha2_224_base(stm_t* stm) {
    uint32_t hs[8] = {
        0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
        0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
    };

    bool has_next_block     = true;
    bool need_paste_one_bit = true;
    size_t all_len = 0, read_len;
    while (stm_has(stm) || has_next_block) {
        uint32_t w[64] = {0};
        all_len += (read_len = stm_read_block(stm, w, 64));

        if (read_len < 64 && need_paste_one_bit) {
            *((uint8_t*)w + read_len) = 128;
            need_paste_one_bit = false;
        }
        if (read_len < 56) {
            *((uint64_t*)w + 7) = be64(all_len * 8);
            has_next_block = false;
        }

        apply_to(w, 16, be32);
        for (size_t i = 16; i < 64; i++) {
            uint32_t s0 = rotr32(w[i-15], 7) ^ rotr32(w[i-15], 18) ^ (w[i-15] >> 3);
            uint32_t s1 = rotr32(w[i-2], 17) ^ rotr32(w[i-2],  19) ^ (w[i-2] >> 10);
            w[i] = w[i-16] +s0 + w[i-7] + s1;
        }

        uint32_t a, b, c, d, e, f, g, h;
        a = hs[0]; b = hs[1]; c = hs[2]; d = hs[3];
        e = hs[4]; f = hs[5]; g = hs[6]; h = hs[7];
        for (size_t i = 0; i < 64; i++) {
            uint32_t s0, s1, ch, ma, t1, t2;
            s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
            s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
            ma = (a & b) ^ (a & c) ^ (b & c);
            ch = (e & f) ^ (~e & g);
            t1 = h + s1 + ch + sha2_224_256_k[i] + w[i];
            t2 = s0 + ma;

            h = g; g = f; f = e; e = t1 + d;
            d = c; c = b; b = a; a = t1 + t2;
        }
        hs[0] += a; hs[1] += b; hs[2] += c; hs[3] += d;
        hs[4] += e; hs[5] += f; hs[6] += g; hs[7] += h;
    }
    
    apply_to(hs, 7, be32);
    chl_sha2_224_ret_t hash = {0};
    memcpy(hash.array, hs, sizeof hs - sizeof hs[7]);
    return hash;
}

chl_sha2_256_ret_t chl_sha2_256_base(stm_t* stm) {
    uint32_t hs[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    bool has_next_block     = true;
    bool need_paste_one_bit = true;
    size_t all_len = 0, read_len;
    while (stm_has(stm) || has_next_block) {
        uint32_t w[64] = {0};
        all_len += (read_len = stm_read_block(stm, w, 64));

        if (read_len < 64 && need_paste_one_bit) {
            *((uint8_t*)w + read_len) = 128;
            need_paste_one_bit = false;
        }
        if (read_len < 56) {
            *((uint64_t*)w + 7) = be64(all_len * 8);
            has_next_block = false;
        }

        apply_to(w, 16, be32);
        for (size_t i = 16; i < 64; i++) {
            uint32_t s0 = rotr32(w[i-15], 7) ^ rotr32(w[i-15], 18) ^ (w[i-15] >> 3);
            uint32_t s1 = rotr32(w[i-2], 17) ^ rotr32(w[i-2],  19) ^ (w[i-2] >> 10);
            w[i] = w[i-16] +s0 + w[i-7] + s1;
        }

        uint32_t a, b, c, d, e, f, g, h;
        a = hs[0]; b = hs[1]; c = hs[2]; d = hs[3];
        e = hs[4]; f = hs[5]; g = hs[6]; h = hs[7];
        for (size_t i = 0; i < 64; i++) {
            uint32_t s0, s1, ch, ma, t1, t2;
            s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
            s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
            ma = (a & b) ^ (a & c) ^ (b & c);
            ch = (e & f) ^ (~e & g);
            t1 = h + s1 + ch + sha2_224_256_k[i] + w[i];
            t2 = s0 + ma;

            h = g; g = f; f = e; e = t1 + d;
            d = c; c = b; b = a; a = t1 + t2;
        }
        hs[0] += a; hs[1] += b; hs[2] += c; hs[3] += d;
        hs[4] += e; hs[5] += f; hs[6] += g; hs[7] += h;
    }
    
    apply_to(hs, 8, be32);
    chl_sha2_256_ret_t hash = {0};
    memcpy(hash.array, hs, sizeof hs);
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

chl_siphash_2_4_ret_t chl_siphash_2_4_base(stm_t* stm, chl_128bit_t key) {
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
    while (stm_has(stm) || has_next_block) {
        uint64_t mi = 0;
        all_len += (read_len =
            stm_read_block(stm, &mi, sizeof mi)
        );

        if (read_len < 8) {
            *((uint8_t*)(&mi) + 7) = all_len & 255;
            has_next_block = false;
        }

        mi = le64(mi);

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