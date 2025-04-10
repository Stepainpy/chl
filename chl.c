#include "chl.h"
#include <stdbool.h>
#include <string.h>
#include "tables.h"

/* Definind stream */

typedef struct stm_t {
    union { const uint8_t* data; FILE* file; } ptr;
    size_t count; // if count == SIZE_MAX then ptr is file, otherwise is span
    struct stm_t* prev;
} stm_t;

#define stm_is_file(stmp) ((stmp)->count == SIZE_MAX)
#define stm_init_span(stmo, p, c) \
(stmo).prev = NULL; (stmo).ptr.data = p; (stmo).count = c
#define stm_init_file(stmo, f) \
(stmo).prev = NULL; (stmo).ptr.file = f; (stmo).count = SIZE_MAX

static int fpeek(FILE* file) {
    const int c = getc(file);
    return c == EOF ? EOF : ungetc(c, file);
}

static bool stm_has(stm_t* stm) {
    if (stm->prev) {
        bool ph = stm_has(stm->prev);
        if (ph) return true;
        stm->prev = NULL;
    }

    if (stm_is_file(stm))
        return fpeek(stm->ptr.file) != EOF;
    return stm->count > 0;
}

static uint8_t stm_read_byte(stm_t* stm) {
    if (stm->prev)
        return stm_read_byte(stm->prev);

    if (stm_is_file(stm))
        return getc(stm->ptr.file);
    return (--stm->count, *stm->ptr.data++);
}

static size_t stm_read_block(stm_t* stm, void* dest, size_t count) {
    if (stm->prev) {
        size_t rdlen = stm_read_block(stm->prev, dest, count);
        if (rdlen == count) return rdlen;
        count -= rdlen;
        dest = (uint8_t*)dest + rdlen;
        stm->prev = NULL;
    }

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

#define uint(bits) uint ## bits ## _t

#define apply_to(arr, size, op) \
for (size_t macroi = 0; macroi < size; macroi++) \
    (arr)[macroi] = op((arr)[macroi])

// obs - One Bit and Size block
#define obs_init \
bool has_next_block     = true; \
bool need_paste_one_bit = true; \
size_t all_len = 0, read_len
#define obs_has_block(stm) stm_has(stm) || has_next_block
#define obs_extract_block_s64(stm, chunk, sizeof_chunk, sval, endian_op, words_cnt) \
all_len += (read_len =                           \
    stm_read_block(stm, chunk, (sizeof_chunk))); \
if (read_len < (sizeof_chunk)                    \
    && need_paste_one_bit) {                     \
    *((uint8_t*)chunk + read_len) = 128;         \
    need_paste_one_bit = false;                  \
} if (read_len < (sizeof_chunk) - 8) {           \
    *((uint64_t*)chunk +                         \
        ((sizeof_chunk) / 8 - 1)) = sval;        \
    has_next_block = false;                      \
} apply_to(chunk, words_cnt, endian_op)

/* Bit rotations */

static inline uint32_t rotl32(uint32_t n, int s) { return n << s | n >> (32 - s); }
static inline uint32_t rotr32(uint32_t n, int s) { return n >> s | n << (32 - s); }
static inline uint64_t rotl64(uint64_t n, int s) { return n << s | n >> (64 - s); }
static inline uint64_t rotr64(uint64_t n, int s) { return n >> s | n << (64 - s); }

/* Defining `calc_span` and `calc_file` as versions of `base` */

#define DO(name, ret) \
static ret CHLN_FUNC(name, base)(stm_t* stm); \
ret CHLN_FUNC(name, calc_span)(const void* source, size_t length) { \
    stm_t stm; stm_init_span(stm, source, length); \
    return CHLN_FUNC(name, base)(&stm); \
} \
ret CHLN_FUNC(name, calc_file)(FILE* src_file) { \
    stm_t stm; stm_init_file(stm, src_file); \
    return CHLN_FUNC(name, base)(&stm); \
}
CHL_LIST_OF_NAMES
#undef DO

#define DO(name, ret, ktype, kname) \
static ret CHLN_FUNC(name, base)(stm_t* stm, ktype kname); \
ret CHLN_FUNC(name, calc_span)(const void* source, size_t length, ktype kname) { \
    stm_t stm; stm_init_span(stm, source, length); \
    return CHLN_FUNC(name, base)(&stm, kname); \
} \
ret CHLN_FUNC(name, calc_file)(FILE* src_file, ktype kname) { \
    stm_t stm; stm_init_file(stm, src_file); \
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

chl_jenkins_ret_t chl_jenkins_base(stm_t* stm) {
    chl_jenkins_ret_t hash = 0;
    while (stm_has(stm)) {
        hash += stm_read_byte(stm);
        hash += hash << 10;
        hash ^= hash >>  6;
    }
    hash += hash <<  3;
    hash ^= hash >> 11;
    hash += hash << 15;
    return hash;
}

static uint32_t murmur3a_mix(uint32_t k) {
    k *= 0xcc9e2d51;
    k = (k << 15) | (k >> 17);
    k *= 0x1b873593;
    return k;
}

chl_murmur3a_ret_t chl_murmur3a_base(stm_t* stm) {
    chl_murmur3a_ret_t hash = 0;

    size_t allread = 0, rdlen;
    while (stm_has(stm)) {
        uint32_t k = 0;
        allread += (rdlen = stm_read_block(stm, &k, sizeof k));
        hash ^= murmur3a_mix(le32(k));
        if (rdlen == sizeof k) {
            hash = (hash << 13) | (hash >> 19);
            hash = hash * 5 + 0xe6546b64;
        }
    }

    hash ^= allread;
    hash ^= hash >> 16;
    hash *= 0x85ebca6b;
    hash ^= hash >> 13;
    hash *= 0xc2b2ae35;
    hash ^= hash >> 16;
    return hash;
}

static const uint32_t md5_s[64] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};

chl_md5_ret_t chl_md5_base(stm_t* stm) {
    uint32_t hs[4] = {
        0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
    };

    obs_init;
    while (obs_has_block(stm)) {
        uint32_t w[16] = {0};

        obs_extract_block_s64(stm, w, 64, le64(all_len * 8), le32, 16);

        uint32_t a = hs[0], b = hs[1], c = hs[2], d = hs[3];
        for (size_t i = 0; i < 64; i++) {
            uint32_t f, g;
            if (i < 16) {
                f = (b & c) | (~b & d);
                g = i;
            } else if (16 <= i && i < 32) {
                f = (d & b) | (~d & c);
                g = (5 * i + 1) % 16;
            } else if (32 <= i && i < 48) {
                f = b ^ c ^ d;
                g = (3 * i + 5) % 16;
            } else {
                f = c ^ (b | ~d);
                g = (7 * i) % 16;
            }

            f += a + md5_k[i] + w[g];
            a = d; d = c; c = b;
            b += rotl32(f, md5_s[i]);
        }
        hs[0] += a; hs[1] += b; hs[2] += c; hs[3] += d;
    }

    apply_to(hs, 4, le32);
    chl_md5_ret_t hash = {0};
    memcpy(hash.array, hs, sizeof hash);
    return hash;
}

chl_sha1_ret_t chl_sha1_base(stm_t* stm) {
    uint32_t hs[5] = {
        0x67452301, 0xEFCDAB89, 0x98BADCFE,
        0x10325476, 0xC3D2E1F0
    };

    obs_init;
    while (obs_has_block(stm)) {
        uint32_t w[80] = {0};

        obs_extract_block_s64(stm, w, 64, be64(all_len * 8), be32, 16);

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

/* Begin SHA2 */

static void sha2_small_alg(stm_t* stm, uint32_t* hs, uint8_t* hash, size_t take) {
    obs_init;
    while (obs_has_block(stm)) {
        uint32_t w[64] = {0};

        obs_extract_block_s64(stm, w, 64, be64(all_len * 8), be32, 16);

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
            t1 = h + s1 + ch + sha2_small_k[i] + w[i];
            t2 = s0 + ma;

            h = g; g = f; f = e; e = t1 + d;
            d = c; c = b; b = a; a = t1 + t2;
        }
        hs[0] += a; hs[1] += b; hs[2] += c; hs[3] += d;
        hs[4] += e; hs[5] += f; hs[6] += g; hs[7] += h;
    }
    
    apply_to(hs, 8, be32);
    memcpy(hash, hs, take * 4);
}

static void sha2_big_alg(stm_t* stm, uint64_t* hs, uint8_t* hash, size_t take) {
    obs_init;
    while (obs_has_block(stm)) {
        uint64_t w[80] = {0};

        // note: usually size_t is uint64_t
        obs_extract_block_s64(stm, w, 128, be64(all_len * 8), be64, 16);

        for (size_t i = 16; i < 80; i++) {
            uint64_t s0 = rotr64(w[i-15], 1) ^ rotr64(w[i-15], 8) ^ (w[i-15] >> 7);
            uint64_t s1 = rotr64(w[i-2], 19) ^ rotr64(w[i-2], 61) ^ (w[i-2]  >> 6);
            w[i] = w[i-16] +s0 + w[i-7] + s1;
        }

        uint64_t a, b, c, d, e, f, g, h;
        a = hs[0]; b = hs[1]; c = hs[2]; d = hs[3];
        e = hs[4]; f = hs[5]; g = hs[6]; h = hs[7];
        for (size_t i = 0; i < 80; i++) {
            uint64_t s0, s1, ch, ma, t1, t2;
            s0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39);
            s1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41);
            ma = (a & b) ^ (a & c) ^ (b & c);
            ch = (e & f) ^ (~e & g);
            t1 = h + s1 + ch + sha2_big_k[i] + w[i];
            t2 = s0 + ma;

            h = g; g = f; f = e; e = t1 + d;
            d = c; c = b; b = a; a = t1 + t2;
        }
        hs[0] += a; hs[1] += b; hs[2] += c; hs[3] += d;
        hs[4] += e; hs[5] += f; hs[6] += g; hs[7] += h;
    }
    
    apply_to(hs, 8, be64);
    memcpy(hash, hs, take * 8);
}

chl_sha2_224_ret_t chl_sha2_224_base(stm_t* stm) {
    chl_sha2_224_ret_t hash = {0};
    uint32_t hs[8] = {
        0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
        0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
    };
    sha2_small_alg(stm, hs, hash.array, 7);
    return hash;
}

chl_sha2_256_ret_t chl_sha2_256_base(stm_t* stm) {
    chl_sha2_256_ret_t hash = {0};
    uint32_t hs[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    sha2_small_alg(stm, hs, hash.array, 8);
    return hash;
}

chl_sha2_384_ret_t chl_sha2_384_base(stm_t* stm) {
    chl_sha2_384_ret_t hash = {0};
    uint64_t hs[8] = {
        0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
        0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4
    };
    sha2_big_alg(stm, hs, hash.array, 6);
    return hash;
}

chl_sha2_512_ret_t chl_sha2_512_base(stm_t* stm) {
    chl_sha2_512_ret_t hash = {0};
    uint64_t hs[8] = {
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
        0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
    };
    sha2_big_alg(stm, hs, hash.array, 8);
    return hash;
}

chl_sha2_512_224_ret_t chl_sha2_512_224_base(stm_t* stm) {
    struct { chl_sha2_512_224_ret_t hash; uint32_t padding; } buffer = {0};
    uint64_t hs[8] = {
        0x8c3d37c819544da2, 0x73e1996689dcd4d6, 0x1dfab7ae32ff9c82, 0x679dd514582f9fcf,
        0x0f6d2b697bd44da8, 0x77e36f7304C48942, 0x3f9d85a86a1d36C8, 0x1112e6ad91d692a1
    };
    sha2_big_alg(stm, hs, (void*)&buffer, 4);
    return buffer.hash;
}

chl_sha2_512_256_ret_t chl_sha2_512_256_base(stm_t* stm) {
    chl_sha2_512_256_ret_t hash = {0};
    uint64_t hs[8] = {
        0x22312194fc2bf72c, 0x9f555fa3c84c64c2, 0x2393b86b6f53b151, 0x963877195940eabd,
        0x96283ee2a88effe3, 0xbe5e1e2553863992, 0x2b0199fc2c85b8aa, 0x0eb72ddC81c52ca2
    };
    sha2_big_alg(stm, hs, hash.array, 4);
    return hash;
}

/* End SHA2 */

/* Begin RIPEMD */

#define ripemd_lentf(u64) le64(le32(u64 >> 32) | le32(u64 & UINT32_MAX))

static uint32_t ripemd_f(size_t i, uint32_t x, uint32_t y, uint32_t z) {
    switch (i / 16) {
        case 0: return x ^ y ^ z;
        case 1: return (x & y) | (~x & z);
        case 2: return (x | ~y) ^ z;
        case 3: return (x & z) | (y & ~z);
        case 4: return x ^ (y | ~z);
        default: return 0;
    }
}

chl_ripemd_160_ret_t chl_ripemd_160_base(stm_t* stm) {
    uint32_t hs[5] = {
        0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0
    };

    obs_init;
    while (obs_has_block(stm)) {
        uint32_t w[16] = {0};

        obs_extract_block_s64(stm, w, sizeof w,
            ripemd_lentf(all_len * 8), le32, 16);

        uint32_t a0, a1, b0, b1, c0, c1, d0, d1, e0, e1, t;
        a0 = hs[0]; b0 = hs[1]; c0 = hs[2]; d0 = hs[3]; e0 = hs[4];
        a1 = hs[0]; b1 = hs[1]; c1 = hs[2]; d1 = hs[3]; e1 = hs[4];
        for (size_t i = 0; i < 80; i++) {
            t = rotl32(a0 + ripemd_f(i, b0, c0, d0) +
                w[ripemd_r[0][i]] + ripemd_1632_k[0][i/16],
                ripemd_s[0][i]) + e0;
            a0 = e0; e0 = d0; d0 = rotl32(c0, 10); c0 = b0; b0 = t;

            t = rotl32(a1 + ripemd_f(79 - i, b1, c1, d1) +
                w[ripemd_r[1][i]] + ripemd_1632_k[1][i/16],
                ripemd_s[1][i]) + e1;
            a1 = e1; e1 = d1; d1 = rotl32(c1, 10); c1 = b1; b1 = t;
        }
        t     = hs[1] + c0 + d1; hs[1] = hs[2] + d0 + e1;
        hs[2] = hs[3] + e0 + a1; hs[3] = hs[4] + a0 + b1;
        hs[4] = hs[0] + b0 + c1; hs[0] = t;
    }

    apply_to(hs, 5, le32);
    chl_ripemd_160_ret_t hash = {0};
    memcpy(hash.array, hs, sizeof hs);
    return hash;
}

chl_ripemd_320_ret_t chl_ripemd_320_base(stm_t* stm) {
    uint32_t hs[10] = {
        0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0,
        0x76543210, 0xFEDCBA98, 0x89ABCDEF, 0x01234567, 0x3C2D1E0F
    };

    obs_init;
    while (obs_has_block(stm)) {
        uint32_t w[16] = {0};

        obs_extract_block_s64(stm, w, sizeof w,
            ripemd_lentf(all_len * 8), le32, 16);

        uint32_t a0, a1, b0, b1, c0, c1, d0, d1, e0, e1, t;
        a0 = hs[0]; b0 = hs[1]; c0 = hs[2]; d0 = hs[3]; e0 = hs[4];
        a1 = hs[5]; b1 = hs[6]; c1 = hs[7]; d1 = hs[8]; e1 = hs[9];
        for (size_t i = 0; i < 80; i++) {
            t = rotl32(a0 + ripemd_f(i, b0, c0, d0) +
                w[ripemd_r[0][i]] + ripemd_1632_k[0][i/16],
                ripemd_s[0][i]) + e0;
            a0 = e0; e0 = d0; d0 = rotl32(c0, 10); c0 = b0; b0 = t;

            t = rotl32(a1 + ripemd_f(79 - i, b1, c1, d1) +
                w[ripemd_r[1][i]] + ripemd_1632_k[1][i/16],
                ripemd_s[1][i]) + e1;
            a1 = e1; e1 = d1; d1 = rotl32(c1, 10); c1 = b1; b1 = t;

            switch (i) {
                case 15: t = b0; b0 = b1; b1 = t; break;
                case 31: t = d0; d0 = d1; d1 = t; break;
                case 47: t = a0; a0 = a1; a1 = t; break;
                case 63: t = c0; c0 = c1; c1 = t; break;
                case 79: t = e0; e0 = e1; e1 = t; break;
            }
        }
        hs[0] += a0; hs[1] += b0; hs[2] += c0; hs[3] += d0; hs[4] += e0;
        hs[5] += a1; hs[6] += b1; hs[7] += c1; hs[8] += d1; hs[9] += e1;
    }

    apply_to(hs, 10, le32);
    chl_ripemd_320_ret_t hash = {0};
    memcpy(hash.array, hs, sizeof hs);
    return hash;
}

chl_ripemd_256_ret_t chl_ripemd_256_base(stm_t* stm) {
    uint32_t hs[8] = {
        0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 
        0x76543210, 0xFEDCBA98, 0x89ABCDEF, 0x01234567
    };

    obs_init;
    while (obs_has_block(stm)) {
        uint32_t w[16] = {0};

        obs_extract_block_s64(stm, w, sizeof w,
            ripemd_lentf(all_len * 8), le32, 16);

        uint32_t a0, a1, b0, b1, c0, c1, d0, d1, t;
        a0 = hs[0]; b0 = hs[1]; c0 = hs[2]; d0 = hs[3];
        a1 = hs[4]; b1 = hs[5]; c1 = hs[6]; d1 = hs[7];
        for (size_t i = 0; i < 64; i++) {
            t = rotl32(a0 + ripemd_f(i, b0, c0, d0) +
                w[ripemd_r[0][i]] + ripemd_1225_k[0][i/16],
                ripemd_s[0][i]);
            a0 = d0; d0 = c0; c0 = b0; b0 = t;

            t = rotl32(a1 + ripemd_f(63 - i, b1, c1, d1) +
                w[ripemd_r[1][i]] + ripemd_1225_k[1][i/16],
                ripemd_s[1][i]);
            a1 = d1; d1 = c1; c1 = b1; b1 = t;

            switch (i) {
                case 15: t = a0; a0 = a1; a1 = t; break;
                case 31: t = b0; b0 = b1; b1 = t; break;
                case 47: t = c0; c0 = c1; c1 = t; break;
                case 63: t = d0; d0 = d1; d1 = t; break;
            }
        }
        hs[0] += a0; hs[1] += b0; hs[2] += c0; hs[3] += d0;
        hs[4] += a1; hs[5] += b1; hs[6] += c1; hs[7] += d1;
    }

    apply_to(hs, 8, le32);
    chl_ripemd_256_ret_t hash = {0};
    memcpy(hash.array, hs, sizeof hs);
    return hash;
}

/* End RIPEMD */

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

// Definition HMAC
#define DO(hfn, block_type) \
CHLN_RET_T_EXP(hmac_##hfn) CHLN_FUNC_EXP(hmac_##hfn, base)(   \
    stm_t* msg_stm, chl_byte_span_t key) {                    \
    block_type ikey = {0}, okey = {0};                        \
    stm_t istm, ostm, fstm;                                   \
                                                              \
    if (key.count > sizeof ikey) {                            \
        stm_t kstm; stm_init_span(kstm, key.data, key.count); \
        CHLN_RET_T(hfn) khash = CHLN_FUNC(hfn, base)(&kstm);  \
        memcpy(ikey.array, khash.array, sizeof khash);        \
        memcpy(okey.array, khash.array, sizeof khash);        \
    } else {                                                  \
        memcpy(ikey.array, key.data, key.count);              \
        memcpy(okey.array, key.data, key.count);              \
    }                                                         \
                                                              \
    apply_to(ikey.array, sizeof ikey, 0x36 ^);                \
    apply_to(okey.array, sizeof okey, 0x5c ^);                \
                                                              \
    msg_stm->prev = &istm;                                    \
    stm_init_span(istm, ikey.array, sizeof ikey);             \
    CHLN_RET_T(hfn) ihash = CHLN_FUNC(hfn, base)(msg_stm);    \
                                                              \
    stm_init_span(ostm, okey.array,  sizeof okey);            \
    stm_init_span(fstm, ihash.array, sizeof ihash);           \
    fstm.prev = &ostm;                                        \
                                                              \
    return CHLN_FUNC(hfn, base)(&fstm);                       \
}
DO(md5,      chl_512bit_t)  DO(sha1,     chl_512bit_t)
DO(sha2_224, chl_512bit_t)  DO(sha2_256, chl_512bit_t)
DO(sha2_384, chl_1024bit_t) DO(sha2_512, chl_1024bit_t)
#undef DO

/* Begin BLAKE2 */

#define BLAKE2_IV32 \
0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, \
0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
#define BLAKE2_IV64 \
0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, \
0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179

#define BLAKE2_MIX(V, bits, s1, s2, s3, s4) \
static void blake2##V##_mix(      \
    uint(bits)* a, uint(bits)* b, \
    uint(bits)* c, uint(bits)* d, \
    uint(bits)  x, uint(bits)  y  \
) {                               \
    *a += *b + x; *d = rotr##bits(*d ^ *a, s1); \
    *c += *d    ; *b = rotr##bits(*b ^ *c, s2); \
    *a += *b + y; *d = rotr##bits(*d ^ *a, s3); \
    *c += *d    ; *b = rotr##bits(*b ^ *c, s4); \
}

#define BLAKE2_G(V, vs, a, b, c, d, p, q) \
blake2##V##_mix(vs+a, vs+b, vs+c, vs+d,   \
    chunk[blake2_s[i][p]], chunk[blake2_s[i][q]])

#define BLAKE2_COMPRESS(V, bits, rs) \
static void blake2##V##_compress(uint(bits)* hs, \
uint(bits)* chunk, size_t comped, bool islast) { \
    uint(bits) vs[16] = { hs[0], hs[1], hs[2],   \
        hs[3], hs[4], hs[5], hs[6], hs[7],       \
        BLAKE2_IV##bits };                       \
                                                 \
    vs[12] ^= comped;                            \
    if (islast) vs[14] = ~vs[14];                \
                                                 \
    for (size_t i = 0; i < rs; i++) {            \
        BLAKE2_G(V, vs, 0, 4,  8, 12,  0,  1);   \
        BLAKE2_G(V, vs, 1, 5,  9, 13,  2,  3);   \
        BLAKE2_G(V, vs, 2, 6, 10, 14,  4,  5);   \
        BLAKE2_G(V, vs, 3, 7, 11, 15,  6,  7);   \
                                                 \
        BLAKE2_G(V, vs, 0, 5, 10, 15,  8,  9);   \
        BLAKE2_G(V, vs, 1, 6, 11, 12, 10, 11);   \
        BLAKE2_G(V, vs, 2, 7,  8, 13, 12, 13);   \
        BLAKE2_G(V, vs, 3, 4,  9, 14, 14, 15);   \
    }                                            \
                                                 \
    apply_to(hs, 8, vs[macroi  ] ^);             \
    apply_to(hs, 8, vs[macroi+8] ^);             \
}

#define BLAKE2_ALG(V, bits, bitblk, bytblk) \
static void blake2##V##_alg(stm_t* stm, chl_byte_span_t key,    \
    void* hash, uint(bits) hbl) {                               \
    CHL_BITS_NAME(bitblk) keyblock = {0}; stm_t kstm = {0};     \
    uint(bits) hs[8] = { BLAKE2_IV##bits };                     \
                                                                \
    if (key.count > bytblk) key.count = bytblk;                 \
    hs[0] ^= 0x01010000 | (uint(bits))key.count << 8 | hbl;     \
                                                                \
    if (key.count > 0) {                                        \
        memcpy(keyblock.array, key.data, key.count);            \
        stm_init_span(kstm, keyblock.array, sizeof keyblock);   \
        stm->prev = &kstm;                                      \
    }                                                           \
                                                                \
    size_t compressed = 0; do {                                 \
        uint(bits) w[16] = {0};                                 \
        compressed += stm_read_block(stm, w, sizeof w);         \
        apply_to(w, 16, le##bits);                              \
        blake2##V##_compress(hs, w, compressed, !stm_has(stm)); \
    } while (stm_has(stm));                                     \
                                                                \
    apply_to(hs, 8, le##bits);                                  \
    memcpy(hash, hs, hbl);                                      \
}

BLAKE2_MIX(s, 32, 16, 12,  8,  7)
BLAKE2_MIX(b, 64, 32, 24, 16, 63)

BLAKE2_COMPRESS(s, 32, 10)
BLAKE2_COMPRESS(b, 64, 12)

BLAKE2_ALG(s, 32,  512, 32)
BLAKE2_ALG(b, 64, 1024, 64)

#define DO(V, bits) \
CHLN_RET_T_EXP(blake2##V##_##bits) CHLN_FUNC_EXP(blake2##V##_##bits, base)( \
    stm_t* stm, CHLN_KEY_T_EXP(blake2##V##_##bits) key) { \
    CHLN_RET_T_EXP(blake2##V##_##bits) hash = {0};        \
    blake2##V##_alg(stm, key, hash.array, sizeof hash);   \
    return hash;                                          \
}
DO(s, 128) DO(s, 160) DO(s, 224) DO(s, 256)
DO(b, 224) DO(b, 256) DO(b, 384) DO(b, 512)
#undef DO

/* End BLAKE2 */