############################################################################
# A toolbox for software optimization of QC-MDPC code based cryptosystems
# Copyright (c) 2017 Nir Drucker, Shay Gueron
# (drucker.nir@gmail.com, shay.gueron@gmail.com)
# The license is detailed in the file LICENSE.md, and applies to this file.
############################################################################

#define __ASM_FILE__
#include "defs.h"

.text    
#void compute_counter_of_unsat(uint8_t unsat_counter[N_BITS],
#                              const uint8_t s[R_BITS],
#                              const uint64_t inv_h0_compressed[W],
#                              const uint64_t inv_h1_compressed[W])

.set unsat_counter, %rdi
.set s, %rsi
.set inv_h0_compressed, %rdx
.set inv_h1_compressed, %rcx

.set tmp32, %eax
.set tmp, %rax

.set itr1, %r10
.set itr2, %r11

.set mask, %zmm31

#define LOW_HALF_ZMMS  i,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
#define ZMM_NUM  16

.macro SUM tag inv_h_compressed res_offset
    xor itr1, itr1
.Lloop\tag:

    .irp LOW_HALF_ZMMS
        vxorps %zmm\i, %zmm\i, %zmm\i
    .endr

    xor itr2, itr2

.Linner_loop\tag:

        #load position
        vbroadcastss 0x4(\inv_h_compressed, itr2, 8), mask
        mov (\inv_h_compressed, itr2, 8), tmp32
        
        #adjust loop offset
        add itr1, tmp 

        vpandq (ZMM_SIZE*0)(s, tmp, 1), mask, %zmm16
        vpandq (ZMM_SIZE*1)(s, tmp, 1), mask, %zmm17
        vpandq (ZMM_SIZE*2)(s, tmp, 1), mask, %zmm18
        vpandq (ZMM_SIZE*3)(s, tmp, 1), mask, %zmm19
        
        vpaddb %zmm0, %zmm16, %zmm0
        vpaddb %zmm1, %zmm17, %zmm1
        vpaddb %zmm2, %zmm18, %zmm2
        vpaddb %zmm3, %zmm19, %zmm3

        vpandq (ZMM_SIZE*4)(s, tmp, 1), mask, %zmm20
        vpandq (ZMM_SIZE*5)(s, tmp, 1), mask, %zmm21
        vpandq (ZMM_SIZE*6)(s, tmp, 1), mask, %zmm22
        vpandq (ZMM_SIZE*7)(s, tmp, 1), mask, %zmm23

        vpaddb %zmm4, %zmm20, %zmm4
        vpaddb %zmm5, %zmm21, %zmm5
        vpaddb %zmm6, %zmm22, %zmm6
        vpaddb %zmm7, %zmm23, %zmm7

        vpandq (ZMM_SIZE*8)(s, tmp, 1), mask, %zmm24
        vpandq (ZMM_SIZE*9)(s, tmp, 1), mask, %zmm25
        vpandq (ZMM_SIZE*10)(s, tmp, 1), mask, %zmm26
        vpandq (ZMM_SIZE*11)(s, tmp, 1), mask, %zmm27

        vpaddb %zmm8, %zmm24, %zmm8
        vpaddb %zmm9, %zmm25, %zmm9
        vpaddb %zmm10, %zmm26, %zmm10
        vpaddb %zmm11, %zmm27, %zmm11

        vpandq (ZMM_SIZE*12)(s, tmp, 1), mask, %zmm28
        vpandq (ZMM_SIZE*13)(s, tmp, 1), mask, %zmm29
        vpandq (ZMM_SIZE*14)(s, tmp, 1), mask, %zmm30
        vpandq (ZMM_SIZE*15)(s, tmp, 1), mask, %zmm31

        vpaddb %zmm12, %zmm28, %zmm12
        vpaddb %zmm13, %zmm29, %zmm13
        vpaddb %zmm14, %zmm30, %zmm14
        vpaddb %zmm15, %zmm31, %zmm15
                
        inc itr2
        cmp $FAKE_W, itr2
        jl .Linner_loop\tag

    .irp LOW_HALF_ZMMS
        vmovdqu64 %zmm\i, \res_offset + (ZMM_SIZE*\i)(unsat_counter, itr1, 1)
    .endr

    add $16*ZMM_SIZE, itr1
    cmp $R_QDQWORDS_BITS, itr1
    jnz .Lloop\tag
.endm

.globl    compute_counter_of_unsat
.hidden   compute_counter_of_unsat
.type     compute_counter_of_unsat,@function
.align    16
compute_counter_of_unsat:
    SUM h0 inv_h0_compressed 0
    SUM h1 inv_h1_compressed R_BITS

    ret
.size    compute_counter_of_unsat,.-compute_counter_of_unsat

