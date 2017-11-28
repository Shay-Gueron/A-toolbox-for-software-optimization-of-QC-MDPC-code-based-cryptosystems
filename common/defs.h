/***************************************************************************
* A toolbox for software optimization of QC-MDPC code based cryptosystems
* Copyright (c) 2017 Nir Drucker, Shay Gueron
* (drucker.nir@gmail.com, shay.gueron@gmail.com)
* The license is detailed in the file LICENSE.md, and applies to this file.
* ***************************************************************************/

#ifndef __DEFS_H_INCLUDED__
#define __DEFS_H_INCLUDED__

////////////////////////////////////////////
//             Basic defs
///////////////////////////////////////////

//Divide by the divider and round up to next integer.
//In asm the symbols '==' and '?' are not allowed therefore if using divide_and_ceil
//in asm files we must ensure with static_assert its validity.
#ifdef __ASM_FILE__
  #define DIVIDE_AND_CEIL(x, divider)  ((x/divider) + 1)
  #define static_assert(COND,MSG) 
#else
  #define DIVIDE_AND_CEIL(x, divider)  ((x/divider) + (x % divider == 0 ? 0 : 1))
  #define static_assert(COND,MSG) typedef char static_assertion_##MSG[(COND)?1:-1]
#endif

#define UNUSED(x) (void)(x)

#define ALIGN(n) __attribute__ ((aligned(n)))

//For clarity of the code.
#define IN 
#define OUT

//Bit manipations
#define BIT(len) (1 << (len))
#define MASK(len) (BIT(len) - 1)
#define SIZEOF_BITS(b) (sizeof(b)*8)

#define _INLINE_ static inline

#define XMM_SIZE 0x10
#define YMM_SIZE 0x20
#define ZMM_SIZE 0x40

#define ALL_YMM_SIZE (16*YMM_SIZE)
#define ALL_ZMM_SIZE (32*ZMM_SIZE)

////////////////////////////////////////////
//             Debug
///////////////////////////////////////////

#ifndef VERBOSE 
  #define VERBOSE 0
#endif

#ifndef __ASM_FILE__
  #if (VERBOSE == 3)
    #define MSG(...)     { printf(__VA_ARGS__); }
    #define DMSG(...)    MSG(__VA_ARGS__)
    #define EDMSG(...)   MSG(__VA_ARGS__)
    #define SEDMSG(...)  MSG(__VA_ARGS__)
  #elif (VERBOSE == 2)
    #define MSG(...)     { printf(__VA_ARGS__); }
    #define DMSG(...)    MSG(__VA_ARGS__)
    #define EDMSG(...)   MSG(__VA_ARGS__)
    #define SEDMSG(...)
  #elif (VERBOSE == 1)
    #define MSG(...)     { printf(__VA_ARGS__); }
    #define DMSG(...)    MSG(__VA_ARGS__)
    #define EDMSG(...)
    #define SEDMSG(...)
  #else
    #define MSG(...)     { printf(__VA_ARGS__); }
    #define DMSG(...)
    #define EDMSG(...)
    #define SEDMSG(...)
  #endif
#endif

////////////////////////////////////////////
//              Parameters
///////////////////////////////////////////

#define R_BITS  32749
#define W       137
#define FAKE_W  261

#define N_BITS   (R_BITS * N0)
#define R_SIZE   DIVIDE_AND_CEIL(R_BITS, 8)
#define R_QW     DIVIDE_AND_CEIL(R_BITS, 64)
#define N_SIZE   DIVIDE_AND_CEIL(N_BITS, 8)
#define N_QW     DIVIDE_AND_CEIL(N_BITS, 64)
#define N_EXTRA_BYTES (8*N_QW - N_SIZE)

#define R_BLOCKS         DIVIDE_AND_CEIL(R_BITS,BLOCK_SIZE)
#define R_PADDED        (R_BLOCKS * BLOCK_SIZE)
#define R_PADDED_SIZE   (R_PADDED/8)
#define R_PADDED_QW     (R_PADDED/64)

#define N_BLOCKS         DIVIDE_AND_CEIL(N_BITS,BLOCK_SIZE)
#define N_PADDED        (N_BLOCKS * BLOCK_SIZE)
#define N_PADDED_SIZE   (N_PADDED/8)
#define N_PADDED_QW     (N_PADDED/64)

#define R_DQWORDS DIVIDE_AND_CEIL(R_SIZE, 16)

#ifdef AVX512
#define R_QDQWORDS_BITS (DIVIDE_AND_CEIL(R_BITS, ALL_ZMM_SIZE) * ALL_ZMM_SIZE)
static_assert((R_BITS % ALL_ZMM_SIZE != 0), rbits_2048_err);

#define N_QDQWORDS_BITS (DIVIDE_AND_CEIL(N_BITS, ALL_ZMM_SIZE) * ALL_ZMM_SIZE)
static_assert((N_BITS % ALL_ZMM_SIZE!= 0), nbits_2048_err);

#else

#define R_DDQWORDS_BITS (DIVIDE_AND_CEIL(R_BITS, ALL_YMM_SIZE) * ALL_YMM_SIZE)
static_assert((R_BITS % ALL_YMM_SIZE != 0), rbits_512_err);

#define N_DDQWORDS_BITS (DIVIDE_AND_CEIL(N_BITS, ALL_YMM_SIZE) * ALL_YMM_SIZE)
static_assert((N_BITS % ALL_YMM_SIZE != 0), nbits_512_err);

#endif

#define LAST_R_QW_LEAD  (R_BITS & MASK(6))
#define LAST_R_QW_TRAIL (64 - LAST_R_QW_LEAD)
#define LAST_R_QW_MASK  MASK(LAST_R_QW_LEAD)

#define LAST_R_BYTE_LEAD  (R_BITS & MASK(3))
#define LAST_R_BYTE_TRAIL (8 - LAST_R_BYTE_LEAD)
#define LAST_R_BYTE_MASK  MASK(LAST_R_BYTE_LEAD)

////////////////////////////////////////////
//              Printing
///////////////////////////////////////////

//#define PRINT_IN_BE
//#define NO_SPACE
//#define NO_NEWLINE

#endif //__TYPES_H_INCLUDED__

