# CHL

CHL - C hashing library. Collection of hash functions

## List of hash functions

Non-Cryptographic functions:
- `djb2`
- `pjw-(32/64)`
- `fnv1[a]-(32/64)`
- `crc32(b/c)`
- `jenkins`
- `md5`
- `sha1`

Cryptographic functions:
- `siphash-2-4`
- `sha2-(224/256/384/512)`
- `sha2-512/(224/256)`
- `ripemd-(160/256/320)`
- `hmac-*`

## Basic API

`chl_xxx_ret_t` - hash function type result  
`chl_xxx_key_t` - key type for hash function (maybe not exist)  
`chl_xxx_calc_span` - find hash value of memory span (ptr + length)  
`chl_xxx_calc_file` - find hash value of file (use `rb` mode)  
where `xxx` - name of hash function.

`CHL_DEFAULT` - name of hash function by default, if not defined then equal `djb2`  
use for macros: `chl_ret_t`, `chl_key_t`, `chl_calc_span`, `chl_calc_file`.