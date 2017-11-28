/***************************************************************************
* A toolbox for software optimization of QC-MDPC code based cryptosystems
* Copyright (c) 2017 Nir Drucker, Shay Gueron
* (drucker.nir@gmail.com, shay.gueron@gmail.com)
* The license is detailed in the file LICENSE.md, and applies to this file.
* ***************************************************************************/

#include "parallel_hash.h"
#include "utilities.h"
#include "stdio.h"
#include "string.h"

#define MAX_REM_LEN (MAX_MB_SLICES * HASH_BLOCK_SIZE)

#pragma pack(push, 1)

//The below struct is a concatination of eight slices and Y.
typedef struct yx_s
{
    union {
        struct {
            sha_hash_t x[MAX_MB_SLICES];
            //We define MAX_REM_LEN and not lrem to be compatible with the standard of C.
            uint8_t y[MAX_REM_LEN];
        };
        uint8_t raw[(MAX_MB_SLICES * sizeof(sha_hash_t)) + MAX_REM_LEN];
    };
} yx_t;

#pragma pack(pop)

_INLINE_ uint64_t compute_slice_len(IN uint64_t la)
{
    //alpha is the number of full blocks.
    const uint64_t alpha = (((la / MAX_MB_SLICES) - SLICE_REM) / HASH_BLOCK_SIZE);
    return ((alpha * HASH_BLOCK_SIZE) + SLICE_REM);
}

void parallel_hash(OUT sha_hash_t* out_hash,
                   IN const uint8_t* m,
                   IN const uint32_t la)
{
    DMSG("    Enter parallel_hash.\n");

    //Calculating how many bytes will go to "parallel" hashing
    //and how many will remind as a tail for later on.
    const uint32_t ls = compute_slice_len(la);
    const uint32_t lrem = (uint32_t)(la - (ls * MAX_MB_SLICES));
    yx_t yx = {0};

#ifdef WIN32
    DMSG("    Len=%u splits into %I64u logical streams (A1..A8) of length %u bytes. ",  la, MAX_MB_SLICES, ls);
    DMSG("Append the logically remaining buffer (Y) of %u - %I64u*%u = %u bytes\n\n", la, MAX_MB_SLICES, ls, lrem);
#else
    DMSG("    Len=%u splits into %llu logical streams (A1..A8) of length %u bytes. ",  la, MAX_MB_SLICES, ls);
    DMSG("Append the logically remaining buffer (Y) of %u - %llu*%u = %u bytes\n\n", la, MAX_MB_SLICES, ls, lrem);
#endif

    EDMSG("    The (original) buffer is:\n    "); print((uint64_t*)m, la*8); DMSG("\n");
    EDMSG("    The 8 SHA digests:\n");

    //Use optimize API for 4 blocks.
    const uint64_t partial_len = (NUM_OF_BLOCKS_IN_MB * ls);
    sha_mb(&yx.x[0], m, partial_len, NUM_OF_BLOCKS_IN_MB);
#if NUM_OF_BLOCKS_IN_MB != MAX_MB_SLICES
    sha_mb(&yx.x[NUM_OF_BLOCKS_IN_MB], &m[partial_len], partial_len, NUM_OF_BLOCKS_IN_MB);
#endif

    for(uint32_t i = 0; i < MAX_MB_SLICES; i++)
    {
        EDMSG("X[%u]:", i); print((uint64_t*)yx.x[i].raw, sizeof(yx.x[i])*8);
    }

    //Copy the reminder (Y).
    memcpy(yx.y, &m[MAX_MB_SLICES * ls], lrem);

    //Compute the final hash (on YX).
    sha(out_hash, sizeof(yx), yx.raw);

    EDMSG("\nY:  "); print((uint64_t*)yx.y, lrem*8);

    DMSG("    Exit parallel_hash.\n");
}

