/***************************************************************************
* A toolbox for software optimization of QC-MDPC code based cryptosystems
* Copyright (c) 2017 Nir Drucker, Shay Gueron
* (drucker.nir@gmail.com, shay.gueron@gmail.com)
* The license is detailed in the file LICENSE.md, and applies to this file.
* ***************************************************************************/

#ifndef _MB_SHA_H_
#define _MB_SHA_H_

#include "types.h"

#define SHA256_HASH_SIZE   32ULL
#define SHA256_HASH_DWORDS (SHA256_HASH_SIZE/4)
#define SHA256_HASH_QWORDS (SHA256_HASH_SIZE/8)

#define SHA384_HASH_SIZE    48ULL
#define SHA384_HASH_QWORDS  (SHA384_HASH_SIZE/8)

#define SHA512_HASH_SIZE    64ULL
#define SHA512_HASH_QWORDS  (SHA512_HASH_SIZE/8)

typedef struct sha256_hash_s
{
    union
    {
         uint8_t  raw[SHA256_HASH_SIZE];
         uint32_t dwords[SHA256_HASH_DWORDS];
         uint64_t qwords[SHA256_HASH_QWORDS];
    };
} sha256_hash_t;

typedef struct sha384_hash_s
{
    union
    {
         uint8_t  raw[SHA384_HASH_SIZE];
         uint64_t qwords[SHA384_HASH_QWORDS];
    };
} sha384_hash_t;

typedef struct sha512_hash_s
{
    union
    {
         uint8_t  raw[SHA512_HASH_SIZE];
         uint64_t qwords[SHA512_HASH_QWORDS];
    };
} sha512_hash_t;

typedef struct {
    uint8_t *ptr;
    uint32_t blocks;
} hash_desc;

#ifdef SHA256 
  #include "sha256.h"
#elif defined(SHA384)
  #include "sha384.h"
#elif defined(SHA512)
  #include "sha512.h"
#endif

int sha(OUT sha_hash_t *hash_out,
        IN const uint32_t byte_length,
        IN const uint8_t *msg);


void sha_mb(OUT sha_hash_t* hash_out,
            IN const uint8_t *msg,
            IN const uint32_t byte_length,
            IN const uint32_t num);

#endif //_MB_SHA_H_
