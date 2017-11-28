/***************************************************************************
* A toolbox for software optimization of QC-MDPC code based cryptosystems
* Copyright (c) 2017 Nir Drucker, Shay Gueron
* (drucker.nir@gmail.com, shay.gueron@gmail.com)
* The license is detailed in the file LICENSE.md, and applies to this file.
* ***************************************************************************/

#ifndef __PARALLEL_HASH_H_INCLUDED__
#define __PARALLEL_HASH_H_INCLUDED__

#include "types.h"
#include "sha.h"

//The parallel_hash algorithm uses the technique described in
// 1) S. Gueron, V. Krasnov. Simultaneous Hashing of Multiple Messages.
//    Journal of Information Security 3:319-325 (2012).
// 2) S. Gueron. A j-Lanes Tree Hashing Mode and j-Lanes SHA-256.
//    Journal of Information Security 4:7-11 (2013).
// See also:
// 3) S. Gueron. Parallelized Hashing via j-Lanes and j-Pointers Tree Modes,
//    with Applications to SHA-256.
//    Journal of Information Security 5:91-113 (2014).
//
// It is designed to convert the serial hashing to a parallelizeable process.
void parallel_hash(OUT sha_hash_t* out_hash,
                   IN const uint8_t* m,
                   IN const uint32_t la);

#endif //__PARALLEL_HASH_H_INCLUDED__

