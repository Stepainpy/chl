#include "chl.h"
#include <stdbool.h>
#include <string.h>

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

static const uint32_t crc32b_table[256] = {
    0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3,
    0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988, 0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91,
    0x1DB71064, 0x6AB020F2, 0xF3B97148, 0x84BE41DE, 0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
    0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC, 0x14015C4F, 0x63066CD9, 0xFA0F3D63, 0x8D080DF5,
    0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172, 0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B,
    0x35B5A8FA, 0x42B2986C, 0xDBBBC9D6, 0xACBCF940, 0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
    0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116, 0x21B4F4B5, 0x56B3C423, 0xCFBA9599, 0xB8BDA50F,
    0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924, 0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D,
    0x76DC4190, 0x01DB7106, 0x98D220BC, 0xEFD5102A, 0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
    0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818, 0x7F6A0DBB, 0x086D3D2D, 0x91646C97, 0xE6635C01,
    0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E, 0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457,
    0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA, 0xFCB9887C, 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
    0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2, 0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB,
    0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0, 0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9,
    0x5005713C, 0x270241AA, 0xBE0B1010, 0xC90C2086, 0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
    0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4, 0x59B33D17, 0x2EB40D81, 0xB7BD5C3B, 0xC0BA6CAD,
    0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A, 0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683,
    0xE3630B12, 0x94643B84, 0x0D6D6A3E, 0x7A6A5AA8, 0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
    0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE, 0xF762575D, 0x806567CB, 0x196C3671, 0x6E6B06E7,
    0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC, 0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5,
    0xD6D6A3E8, 0xA1D1937E, 0x38D8C2C4, 0x4FDFF252, 0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
    0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60, 0xDF60EFC3, 0xA867DF55, 0x316E8EEF, 0x4669BE79,
    0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236, 0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F,
    0xC5BA3BBE, 0xB2BD0B28, 0x2BB45A92, 0x5CB36A04, 0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,
    0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A, 0x9C0906A9, 0xEB0E363F, 0x72076785, 0x05005713,
    0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38, 0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21,
    0x86D3D2D4, 0xF1D4E242, 0x68DDB3F8, 0x1FDA836E, 0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
    0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C, 0x8F659EFF, 0xF862AE69, 0x616BFFD3, 0x166CCF45,
    0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2, 0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB,
    0xAED16A4A, 0xD9D65ADC, 0x40DF0B66, 0x37D83BF0, 0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
    0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6, 0xBAD03605, 0xCDD70693, 0x54DE5729, 0x23D967BF,
    0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94, 0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D
};

static const uint32_t crc32c_table[256] = {
    0x00000000, 0xF26B8303, 0xE13B70F7, 0x1350F3F4, 0xC79A971F, 0x35F1141C, 0x26A1E7E8, 0xD4CA64EB,
    0x8AD958CF, 0x78B2DBCC, 0x6BE22838, 0x9989AB3B, 0x4D43CFD0, 0xBF284CD3, 0xAC78BF27, 0x5E133C24,
    0x105EC76F, 0xE235446C, 0xF165B798, 0x030E349B, 0xD7C45070, 0x25AFD373, 0x36FF2087, 0xC494A384,
    0x9A879FA0, 0x68EC1CA3, 0x7BBCEF57, 0x89D76C54, 0x5D1D08BF, 0xAF768BBC, 0xBC267848, 0x4E4DFB4B,
    0x20BD8EDE, 0xD2D60DDD, 0xC186FE29, 0x33ED7D2A, 0xE72719C1, 0x154C9AC2, 0x061C6936, 0xF477EA35,
    0xAA64D611, 0x580F5512, 0x4B5FA6E6, 0xB93425E5, 0x6DFE410E, 0x9F95C20D, 0x8CC531F9, 0x7EAEB2FA,
    0x30E349B1, 0xC288CAB2, 0xD1D83946, 0x23B3BA45, 0xF779DEAE, 0x05125DAD, 0x1642AE59, 0xE4292D5A,
    0xBA3A117E, 0x4851927D, 0x5B016189, 0xA96AE28A, 0x7DA08661, 0x8FCB0562, 0x9C9BF696, 0x6EF07595,
    0x417B1DBC, 0xB3109EBF, 0xA0406D4B, 0x522BEE48, 0x86E18AA3, 0x748A09A0, 0x67DAFA54, 0x95B17957,
    0xCBA24573, 0x39C9C670, 0x2A993584, 0xD8F2B687, 0x0C38D26C, 0xFE53516F, 0xED03A29B, 0x1F682198,
    0x5125DAD3, 0xA34E59D0, 0xB01EAA24, 0x42752927, 0x96BF4DCC, 0x64D4CECF, 0x77843D3B, 0x85EFBE38,
    0xDBFC821C, 0x2997011F, 0x3AC7F2EB, 0xC8AC71E8, 0x1C661503, 0xEE0D9600, 0xFD5D65F4, 0x0F36E6F7,
    0x61C69362, 0x93AD1061, 0x80FDE395, 0x72966096, 0xA65C047D, 0x5437877E, 0x4767748A, 0xB50CF789,
    0xEB1FCBAD, 0x197448AE, 0x0A24BB5A, 0xF84F3859, 0x2C855CB2, 0xDEEEDFB1, 0xCDBE2C45, 0x3FD5AF46,
    0x7198540D, 0x83F3D70E, 0x90A324FA, 0x62C8A7F9, 0xB602C312, 0x44694011, 0x5739B3E5, 0xA55230E6,
    0xFB410CC2, 0x092A8FC1, 0x1A7A7C35, 0xE811FF36, 0x3CDB9BDD, 0xCEB018DE, 0xDDE0EB2A, 0x2F8B6829,
    0x82F63B78, 0x709DB87B, 0x63CD4B8F, 0x91A6C88C, 0x456CAC67, 0xB7072F64, 0xA457DC90, 0x563C5F93,
    0x082F63B7, 0xFA44E0B4, 0xE9141340, 0x1B7F9043, 0xCFB5F4A8, 0x3DDE77AB, 0x2E8E845F, 0xDCE5075C,
    0x92A8FC17, 0x60C37F14, 0x73938CE0, 0x81F80FE3, 0x55326B08, 0xA759E80B, 0xB4091BFF, 0x466298FC,
    0x1871A4D8, 0xEA1A27DB, 0xF94AD42F, 0x0B21572C, 0xDFEB33C7, 0x2D80B0C4, 0x3ED04330, 0xCCBBC033,
    0xA24BB5A6, 0x502036A5, 0x4370C551, 0xB11B4652, 0x65D122B9, 0x97BAA1BA, 0x84EA524E, 0x7681D14D,
    0x2892ED69, 0xDAF96E6A, 0xC9A99D9E, 0x3BC21E9D, 0xEF087A76, 0x1D63F975, 0x0E330A81, 0xFC588982,
    0xB21572C9, 0x407EF1CA, 0x532E023E, 0xA145813D, 0x758FE5D6, 0x87E466D5, 0x94B49521, 0x66DF1622,
    0x38CC2A06, 0xCAA7A905, 0xD9F75AF1, 0x2B9CD9F2, 0xFF56BD19, 0x0D3D3E1A, 0x1E6DCDEE, 0xEC064EED,
    0xC38D26C4, 0x31E6A5C7, 0x22B65633, 0xD0DDD530, 0x0417B1DB, 0xF67C32D8, 0xE52CC12C, 0x1747422F,
    0x49547E0B, 0xBB3FFD08, 0xA86F0EFC, 0x5A048DFF, 0x8ECEE914, 0x7CA56A17, 0x6FF599E3, 0x9D9E1AE0,
    0xD3D3E1AB, 0x21B862A8, 0x32E8915C, 0xC083125F, 0x144976B4, 0xE622F5B7, 0xF5720643, 0x07198540,
    0x590AB964, 0xAB613A67, 0xB831C993, 0x4A5A4A90, 0x9E902E7B, 0x6CFBAD78, 0x7FAB5E8C, 0x8DC0DD8F,
    0xE330A81A, 0x115B2B19, 0x020BD8ED, 0xF0605BEE, 0x24AA3F05, 0xD6C1BC06, 0xC5914FF2, 0x37FACCF1,
    0x69E9F0D5, 0x9B8273D6, 0x88D28022, 0x7AB90321, 0xAE7367CA, 0x5C18E4C9, 0x4F48173D, 0xBD23943E,
    0xF36E6F75, 0x0105EC76, 0x12551F82, 0xE03E9C81, 0x34F4F86A, 0xC69F7B69, 0xD5CF889D, 0x27A40B9E,
    0x79B737BA, 0x8BDCB4B9, 0x988C474D, 0x6AE7C44E, 0xBE2DA0A5, 0x4C4623A6, 0x5F16D052, 0xAD7D5351
};

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

chl_siphash_2_4_ret_t chl_siphash_2_4_base(stm_t* stm, chl_array_128b_t key) {
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