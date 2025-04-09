# CHL

CHL - C hashing library. Collection of hash functions

## List of hash functions

Non-Cryptographic functions:
- `djb2`
- `PJW-(32/64)`
- `FNV1[a]-(32/64)`
- `CRC32(b/c)`
- `jenkins`
- `MurMur3a`
- `MD5`
- `SHA1`

Cryptographic functions:
- `SipHash-2-4`
- `SHA2-(224/256/384/512)`
- `SHA2-512/(224/256)`
- `HMAC-(MD5/SHA1/SHA2)`
- `RIPEMD-(160/256/320)`
- `BLAKE2b-(224/256/384/512)`
- `BLAKE2s-(128/160/224/256)`

## Basic API

`chl_xxx_ret_t` - hash function type result  
`chl_xxx_key_t` - key type for hash function (maybe not exist)  
`chl_xxx_calc_span` - find hash value of memory span (ptr + length)  
`chl_xxx_calc_file` - find hash value of file (use `rb` mode)  
where `xxx` - name of hash function.

`CHL_DEFAULT` - name of hash function by default, if not defined then equal `djb2`  
use for macros: `chl_ret_t`, `chl_key_t`, `chl_calc_span`, `chl_calc_file`.