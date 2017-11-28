/***************************************************************************
* A toolbox for software optimization of QC-MDPC code based cryptosystems
* Copyright (c) 2017 Nir Drucker, Shay Gueron
* (drucker.nir@gmail.com, shay.gueron@gmail.com)
* The license is detailed in the file LICENSE.md, and applies to this file.
* ***************************************************************************/

#ifndef __TYPES_H_INCLUDED__
#define __TYPES_H_INCLUDED__

#include "defs.h"

//GCC definitions.
typedef unsigned char          uint8_t;
typedef unsigned short int     uint16_t;
typedef unsigned int           uint32_t;
typedef unsigned long long     uint64_t;
//Some assembly files are relying on this sizes!.
static_assert((sizeof(uint8_t) == 1), uint8_t_err);
static_assert((sizeof(uint16_t) == 2), uint16_t_err);
static_assert((sizeof(uint32_t) == 4), uint32_t_err);
static_assert((sizeof(uint64_t) == 8), uint64_t_err);

typedef struct uint128_s
{
    union
    {
        uint8_t bytes[16];
        uint32_t dw[4];
        uint64_t qw[2];
    };
} uint128_t;

//Make sure no compiler optimizations.
#pragma pack(push, 1)

typedef struct r_s 
{ 
    uint8_t raw[R_SIZE]; 
} r_t;

typedef struct e_s
{ 
    uint8_t raw[N_SIZE]; 
} e_t;

typedef struct idx_s
{
    uint32_t val;
#ifdef CONSTANT_TIME
    uint32_t used;
#endif
} idx_t;

typedef struct compressed_idx_w_s
{
  idx_t val[FAKE_W];
} compressed_idx_w_t;

//R in redundant representation.
typedef struct red_r_s 
{ 
    uint8_t raw[R_BITS];
} red_r_t;

typedef struct seed_s
{
    union {
        uint8_t  raw[32];
        uint64_t qwords[4];
    };
} seed_t;

#pragma pack(pop)

#endif //__TYPES_H_INCLUDED__

