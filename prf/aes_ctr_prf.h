/***************************************************************************
* A toolbox for software optimization of QC-MDPC code based cryptosystems
* Copyright (c) 2017 Nir Drucker, Shay Gueron
* (drucker.nir@gmail.com, shay.gueron@gmail.com)
* The license is detailed in the file LICENSE.md, and applies to this file.
* ***************************************************************************/

#ifndef __AES_CTR_REF_H_INCLUDED__
#define __AES_CTR_REF_H_INCLUDED__

#include "types.h"
#include "aes.h"

//////////////////////////////
//        Types
/////////////////////////////

typedef struct aes_ctr_prf_state_s
{
    uint128_t ctr;
    uint128_t buffer;
    uint8_t   key[60*4];
    uint32_t  rem_invokations;
    uint8_t   pos;
} aes_ctr_prf_state_t;

//////////////////////////////
//        Methods
/////////////////////////////

status_t init_aes_ctr_prf_state(OUT aes_ctr_prf_state_t* s,
                                IN  const uint32_t maxInvokations,
                                IN  const seed_t* seed);

status_t aes_ctr_prf(OUT uint8_t* a,
                     IN OUT aes_ctr_prf_state_t* s,
                     IN const uint32_t len);

#endif //__AES_CTR_REF_H_INCLUDED__

