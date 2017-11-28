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

#define LOW_HALF_YMMS  i,0,1,2,3,4,5,6,7
#define YMM_NUM  8
#define TOTAL_YMMS_SIZE  (YMM_NUM*YMM_SIZE)

.set mask, %ymm15

.macro SUM tag inv_h_compressed res_offset
    xor itr1, itr1
.Lloop\tag:

    .irp LOW_HALF_YMMS
        vxorps %ymm\i, %ymm\i, %ymm\i
    .endr

    xor itr2, itr2

.Linner_loop\tag:

        #load position
        vbroadcastss 0x4(\inv_h_compressed, itr2, 8), mask
        mov (\inv_h_compressed, itr2, 8), tmp32
        
        #adjust loop offset
        add itr1, tmp 

        vpand (YMM_SIZE*0)(s, tmp, 1), mask, %ymm8
        vpand (YMM_SIZE*1)(s, tmp, 1), mask, %ymm9
        vpand (YMM_SIZE*2)(s, tmp, 1), mask, %ymm10
        vpand (YMM_SIZE*3)(s, tmp, 1), mask, %ymm11
        vpand (YMM_SIZE*4)(s, tmp, 1), mask, %ymm12
        vpand (YMM_SIZE*5)(s, tmp, 1), mask, %ymm13

        vpaddb %ymm0, %ymm8, %ymm0
        vpaddb %ymm1, %ymm9, %ymm1
        vpaddb %ymm2, %ymm10, %ymm2
        vpaddb %ymm3, %ymm11, %ymm3
        vpaddb %ymm4, %ymm12, %ymm4
        
        vpand (YMM_SIZE*6)(s, tmp, 1), mask, %ymm14
        vpand (YMM_SIZE*7)(s, tmp, 1), mask, %ymm15
        
        vpaddb %ymm5, %ymm13, %ymm5
        vpaddb %ymm6, %ymm14, %ymm6
        vpaddb %ymm7, %ymm15, %ymm7
        
        inc itr2
        cmp $FAKE_W, itr2
        jl .Linner_loop\tag

    .irp LOW_HALF_YMMS
        vmovdqu %ymm\i, \res_offset + (YMM_SIZE*\i)(unsat_counter, itr1, 1)
    .endr

    add $TOTAL_YMMS_SIZE, itr1
    cmp $R_DDQWORDS_BITS, itr1
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
