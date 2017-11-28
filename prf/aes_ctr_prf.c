/***************************************************************************
* A toolbox for software optimization of QC-MDPC code based cryptosystems
* Copyright (c) 2017 Nir Drucker, Shay Gueron
* (drucker.nir@gmail.com, shay.gueron@gmail.com)
* The license is detailed in the file LICENSE.md, and applies to this file.
* ***************************************************************************/

#include "aes_ctr_prf.h"
#include "string.h"
#include "stdio.h"
#include "utilities.h"

status_t init_aes_ctr_prf_state(OUT aes_ctr_prf_state_t* s,
                                IN const uint32_t maxInvokations,
                                IN const seed_t* seed)
{
    if (maxInvokations == 0)
    {
        return E_AES_CTR_PRF_INIT_FAIL;
    }
    
    //Set the Key schedule (from seed).
    AES_256_Key_Expansion (s->key, seed->raw);
 
    //Initialize buffer and counter
    s->ctr.qw[0] = 0;
    s->ctr.qw[1] = 0;

    s->pos = AES256_BLOCK_SIZE;
    s->rem_invokations = maxInvokations;
    
    SEDMSG("    Init aes_prf_ctr state:\n");
    SEDMSG("      s.pos = %d\n", s->pos); 
    SEDMSG("      s.rem_invokations = %u\n", s->rem_invokations); 
    SEDMSG("      s.ctr = 0x"); //print(s->ctr.qw, sizeof(s->ctr)*8);
    
    return SUCCESS;
}

_INLINE_ status_t perform_aes(OUT uint8_t* ct, IN OUT aes_ctr_prf_state_t* s)
{
    if(s->rem_invokations == 0)
    {
        return E_AES_OVER_USED;
    }

    AES256_Enc_Intrinsic(ct, s->ctr.bytes, s->key);

    s->ctr.qw[0]++;
    s->rem_invokations--;
    
    return SUCCESS;
}

status_t aes_ctr_prf(OUT uint8_t* a,
                     IN aes_ctr_prf_state_t* s,
                     IN const uint32_t len)
{
    status_t res = SUCCESS;

    //When Len i smaller then whats left in the buffer 
    //No need in additional AES.
    if ((len + s->pos) <= AES256_BLOCK_SIZE)
    {
        memcpy(a, &s->buffer.bytes[s->pos], len);
        s->pos += len;
        
        return res;
    }

    //if s.pos != AES256_BLOCK_SIZE then copy whats left in the buffer.
    //else copy zero bytes.
    uint32_t idx = AES256_BLOCK_SIZE - s->pos;
    memcpy(a, &s->buffer.bytes[s->pos], idx);
    
    //Init s.pos;
    s->pos = 0;
    
    //Copy full AES blocks.
    while((len - idx) >= AES256_BLOCK_SIZE)
    {
        res = perform_aes(&a[idx], s);                    CHECK_STATUS(res);
        idx += AES256_BLOCK_SIZE;
    }
    
    res = perform_aes(s->buffer.bytes, s);                CHECK_STATUS(res);

    //Copy the tail.
    s->pos = len - idx;
    memcpy(&a[idx], s->buffer.bytes, s->pos);

EXIT:
    return res;
}

