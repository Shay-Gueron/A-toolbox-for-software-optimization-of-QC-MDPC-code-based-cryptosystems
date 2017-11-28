/***************************************************************************
* A toolbox for software optimization of QC-MDPC code based cryptosystems
* Copyright (c) 2017 Nir Drucker, Shay Gueron
* (drucker.nir@gmail.com, shay.gueron@gmail.com)
* The license is detailed in the file LICENSE.md, and applies to this file.
* ***************************************************************************/

#ifndef _GF2MUL_H_
#define _GF2MUL_H_

#include "types.h"


//Found in the assembly files.
//size is the number of bytes in a/b/res (all equal!)
extern void gf2x_add_avx2(OUT const uint8_t *res, 
                          IN const uint8_t *a, 
                          IN const uint8_t *b, 
                          IN const uint64_t size);

//A wrapper for other gf2x_add implementations.
_INLINE_ void gf2x_add(const uint8_t *res, const uint8_t *a, const uint8_t *b, const uint64_t size)
{
    gf2x_add_avx2(res, a, b, size);
}

//res = a*b mod (x^r - 1)
//the caller must allocate twice the size of res!
void gf2x_mod_mul(OUT uint64_t *res, 
                  IN const uint64_t *a, 
                  IN const uint64_t *b);

#endif //_GF2MUL_H_
