/***************************************************************************
* A toolbox for software optimization of QC-MDPC code based cryptosystems
* Copyright (c) 2017 Nir Drucker, Shay Gueron
* (drucker.nir@gmail.com, shay.gueron@gmail.com)
* The license is detailed in the file LICENSE.md, and applies to this file.
* ***************************************************************************/

#ifndef __AES_H_INCLUDED__
#define __AES_H_INCLUDED__

#include "types.h"

#define AES256_KEY_SIZE 32ULL
#define AES256_KEY_BITS (AES256_KEY_SIZE*8)
#define AES256_BLOCK_SIZE 16ULL

#define MAX_AES_INVOKATION (MASK(32))

void AES_256_Key_Expansion (OUT uint8_t *ks, IN  const uint8_t *key);

void AES256_Enc_Intrinsic(OUT const uint8_t* ct,
                          IN  const uint8_t* pt,
                          IN  const uint8_t* ks);


#endif //__AES_H_INCLUDED__

