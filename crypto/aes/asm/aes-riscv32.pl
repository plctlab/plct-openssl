#! /usr/bin/env perl
# Copyright 2007-2020 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the ";License";).  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html



# AES for riscv32.

# April 2021.
#
$output = $#ARGV >= 0 && $ARGV[$#ARGV] =~ m|\.\w+$| ? pop : undef;
$flavour = $#ARGV >= 0 && $ARGV[0] !~ m|\.| ? shift : undef;

if ($flavour=~ /3[12]/) {
    $SIZE_T=4;
    $g="";
} else {
    $SIZE_T=8;
    $g="g";
}

$output and open STDOUT,">$output";

$code.=<<___;
//
// Rotate value in RS1 right by IMM. Use TMP as scratch regiser.
// RD may equal RS1. TMP may not equal RD or RS1.
.macro ROR32I RD, TMP, RS1, IMM
    srli    \\TMP, \\RS1, \\IMM
    slli    \\RD , \\RS1, (32-\\IMM)
    or      \\RD , \\RD , \\TMP
.endm

//
// Load the byte-aligned AES state from pointer in CK
// - Each column is loaded into the T* registers.
// - The X* registers are temps.
//
.macro AES_LOAD_STATE T0, T1, T2, T3, CK, X0, X1, X2, X3

#if ((AES_BYTE_ALIGNED == 1) || (defined(AES_BYTE_ALIGNED)))

    lbu     \\T0,  3(\\CK)
    lbu     \\T1,  7(\\CK)
    lbu     \\T2, 11(\\CK)
    lbu     \\T3, 15(\\CK)
    slli    \\T0,\\T0, 8
    slli    \\T1,\\T1, 8
    slli    \\T2,\\T2, 8
    slli    \\T3,\\T3, 8
    lbu     \\X0,  2(\\CK)
    lbu     \\X1,  6(\\CK)
    lbu     \\X2, 10(\\CK)
    lbu     \\X3, 14(\\CK)
    or      \\T0, \\T0, \\X0
    or      \\T1, \\T1, \\X1
    or      \\T2, \\T2, \\X2
    or      \\T3, \\T3, \\X3
    slli    \\T0,\\T0, 8
    slli    \\T1,\\T1, 8
    slli    \\T2,\\T2, 8
    slli    \\T3,\\T3, 8
    lbu     \\X0,  1(\\CK)
    lbu     \\X1,  5(\\CK)
    lbu     \\X2,  9(\\CK)
    lbu     \\X3, 13(\\CK)
    or      \\T0, \\T0, \\X0
    or      \\T1, \\T1, \\X1
    or      \\T2, \\T2, \\X2
    or      \\T3, \\T3, \\X3
    slli    \\T0,\\T0, 8
    slli    \\T1,\\T1, 8
    slli    \\T2,\\T2, 8
    slli    \\T3,\\T3, 8
    lbu     \\X0,  0(\\CK)
    lbu     \\X1,  4(\\CK)
    lbu     \\X2,  8(\\CK)
    lbu     \\X3, 12(\\CK)
    or      \\T0, \\T0, \\X0
    or      \\T1, \\T1, \\X1
    or      \\T2, \\T2, \\X2
    or      \\T3, \\T3, \\X3

#else

    lw      \\T0, 0(\\CK)
    lw      \\T1, 4(\\CK)
    lw      \\T2, 8(\\CK)
    lw      \\T3,12(\\CK)

#endif

.endm

//
// Dump the AES state from column-wise registers into a byte-aligned array.
//
.macro AES_DUMP_STATE T0, T1, T2, T3, CT

#if ((AES_BYTE_ALIGNED == 1) || (defined(AES_BYTE_ALIGNED)))

    sb      \\T0,  0(\\CT)
    sb      \\T1,  4(\\CT)
    sb      \\T2,  8(\\CT)
    sb      \\T3, 12(\\CT)
    srli    \\T0, \\T0, 8
    srli    \\T1, \\T1, 8
    srli    \\T2, \\T2, 8
    srli    \\T3, \\T3, 8
    sb      \\T0,  1(\\CT)
    sb      \\T1,  5(\\CT)
    sb      \\T2,  9(\\CT)
    sb      \\T3, 13(\\CT)
    srli    \\T0, \\T0, 8
    srli    \\T1, \\T1, 8
    srli    \\T2, \\T2, 8
    srli    \\T3, \\T3, 8
    sb      \\T0,  2(\\CT)
    sb      \\T1,  6(\\CT)
    sb      \\T2, 10(\\CT)
    sb      \\T3, 14(\\CT)
    srli    \\T0, \\T0, 8
    srli    \\T1, \\T1, 8
    srli    \\T2, \\T2, 8
    srli    \\T3, \\T3, 8
    sb      \\T0,  3(\\CT)
    sb      \\T1,  7(\\CT)
    sb      \\T2, 11(\\CT)
    sb      \\T3, 15(\\CT)

#else

    sw      \\T0, 0(\\CT)
    sw      \\T1, 4(\\CT)
    sw      \\T2, 8(\\CT)
    sw      \\T3,12(\\CT)
    
#endif
.endm
___

$C0="a2";
$C1="a3";
$C2="a4";
$C3="a5";

$RK="a0";
$RKP="a6";
$CK="a1";

$RKE="t0";
$RCP="t1";
$RCT="t2";

$T1="t3";
$T2="t4";

$code.=<<___;
.data

//
// Round constants for the AES Key Schedule
aes_round_const:
    .byte 0x01, 0x02, 0x04, 0x08, 0x10
    .byte 0x20, 0x40, 0x80, 0x1b, 0x36 


.text

.func     aes_128_set_encrypt_key
.global   aes_128_set_encrypt_key
aes_128_set_encrypt_key:       // a0 - uint32_t rk [AES_128_RK_WORDS]
                                // a1 - uint8_t  ck [AES_128_CK_BYTE ]

    lw      $C0,  0($CK)
    lw      $C1,  4($CK)
    lw      $C2,  8($CK)
    lw      $C3, 12($CK)
    
    mv      $RKP, $RK
    addi    $RKE, $RK, 160        //="t0";= rke= rk + 40
    la      $RCP, aes_round_const//="t1";= round constant pointer

.aes_128_enc_ks_l0:             // Loop start

    sw      $C0,  0($RKP)         // rkp[0]=="a2";
    sw      $C1,  4($RKP)         // rkp[1]=="a3";
    sw      $C2,  8($RKP)         // rkp[2]= a4
    sw      $C3, 12($RKP)         // rkp[3]= a5
                                
                                // if rke==rkp, return - loop break
    beq     $RKE, $RKP, .aes_128_enc_ks_finish

    addi    $RKP, $RKP, 16        // increment rkp

    lbu     $RCT, 0($RCP)         // Load round constant byte
    addi    $RCP, $RCP, 1         // Increment round constant byte
    xor     $C0, $C0, $RCT         // c0 ^= rcp

    ROR32I $T1, $T2, $C3, 8        // tr= ROR32(c3, 8)
    aes32esi $C0, $C0, $T1, 0   // tr= sbox(tr)
    aes32esi $C0, $C0, $T1, 1   //
    aes32esi $C0, $C0, $T1, 2   //
    aes32esi $C0, $C0, $T1, 3   //

    xor     $C1, $C1, $C0          // C1 ^= C0
    xor     $C2, $C2, $C1          // C2 ^= C1
    xor     $C3, $C3, $C2          // C3 ^= C2

    j .aes_128_enc_ks_l0        // Loop continue

.aes_128_enc_ks_finish:
    ret

.endfunc
___

$RK="a0";
$RKP="a2";
$RKE="a3";
$T0="t0";
$T1="t1";

$code.=<<___;
.func     aes_128_set_decrypt_key
.global   aes_128_set_decrypt_key
aes_128_set_decrypt_key:           // a0 - uint32_t rk [AES_128_RK_WORDS]
                                    // a1 - uint8_t  ck [AES_128_CK_BYTE ]

    addi    sp, sp, -16              // Save stack
    sw      ra, 0(sp)

    call    aes_128_set_encrypt_key //

    addi    $RKP, $RK, 16              // a0= &rk[ 4]
    addi    $RKE, $RK, 160             // a1= &rk[40]

    .dec_ks_loop_128:
        
        lw   $T0, 0($RKP)              // Load key word

        li        $T1, 0
        aes32esi  $T1, $T1, $T0, 0          // Sub Word Forward
        aes32esi  $T1, $T1, $T0, 1 
        aes32esi  $T1, $T1, $T0, 2
        aes32esi  $T1, $T1, $T0, 3

        li        $T0, 0
        aes32dsmi $T0, $T0, $T1, 0          // Sub Word Inverse & Inverse MixColumns
        aes32dsmi $T0, $T0, $T1, 1
        aes32dsmi $T0, $T0, $T1, 2
        aes32dsmi $T0, $T0, $T1, 3

        sw   $T0, 0($RKP)             // Store key word.

        addi $RKP, $RKP, 4            // Increment round key pointer
        bne  $RKP, $RKE, .dec_ks_loop_128 // Finished yet?

    lw      ra, 0(sp)
    addi    sp, sp,  16

    ret
.endfunc
___

$C0="a2";
$C1="a3";
$C2="a4";
$C3="a5";
$C4="a7";
$C5="t5";

$RK="a0";
$RKP="a6";
$CK="a1";

$RKE="t0";
$RCP="t1";
$RCT="t4";

$T1="t3";
$T2="t4";

$code.=<<___;

.text


.func     aes_192_set_encrypt_key
.global   aes_192_set_encrypt_key
aes_192_set_encrypt_key:       // a0 - uint32_t rk [AES_192_RK_WORDS]
                                // a1 - uint8_t  ck [AES_192_CK_BYTE ]

    lw  $C0,  0($CK)
    lw  $C1,  4($CK)
    lw  $C2,  8($CK)
    lw  $C3, 12($CK)
    lw  $C4, 16($CK)
    lw  $C5, 20($CK)
    
    mv      $RKP, $RK
    addi    $RKE, $RK, 48*4       //
    la      $RCP, aes_round_const//="t1";= round constant pointer

.aes_192_enc_ks_l0:             // Loop start

    sw      $C0,  0($RKP)         // rkp[0]
    sw      $C1,  4($RKP)         // rkp[1]
    sw      $C2,  8($RKP)         // rkp[2]
    sw      $C3, 12($RKP)         // rkp[3]
                                
                                // if rke==rkp, return - loop break
    beq     $RKE, $RKP, .aes_192_enc_ks_finish
    
    sw      $C4, 16($RKP)         // rkp[4]
    sw      $C5, 20($RKP)         // rkp[5]

    addi    $RKP, $RKP, 24        // increment rkp

    lbu     $RCT, 0($RCP)         // Load round constant byte
    addi    $RCP, $RCP, 1         // Increment round constant byte
    xor     $C0, $C0, $RCT         // c0 ^= rcp

    ROR32I $T1, $T2, $C5, 8        // tr= ROR32(c3, 8)
    aes32esi $C0, $C0, $T1, 0   // tr= sbox(tr)
    aes32esi $C0, $C0, $T1, 1   //
    aes32esi $C0, $C0, $T1, 2   //
    aes32esi $C0, $C0, $T1, 3   //

    xor     $C1, $C1, $C0          // C1 ^= C0
    xor     $C2, $C2, $C1          // C2 ^= C1
    xor     $C3, $C3, $C2          // C3 ^= C2
    xor     $C4, $C4, $C3          // C4 ^= C3
    xor     $C5, $C5, $C4          // C5 ^= C4

    j .aes_192_enc_ks_l0        // Loop continue

.aes_192_enc_ks_finish:
    ret

.endfunc
___

    
$RK="a0";
$RKP="a2";
$RKE="a3";
$T0="t0";
$T1="t1";
$code.=<<___;
.func     aes_192_set_decrypt_key
.global   aes_192_set_decrypt_key
aes_192_set_decrypt_key:           // a0 - uint32_t rk [AES_192_RK_WORDS]
                                    // a1 - uint8_t  ck [AES_192_CK_BYTE ]
   

    addi    sp, sp, -16              // Save stack
    sw      ra, 0(sp)

    call    aes_192_set_encrypt_key //

    addi    $RKP, $RK, 16              // a0= &rk[ 4]
    addi    $RKE, $RK, 48*4            //

    .dec_ks_loop_192:
        
        lw   $T0, 0($RKP)              // Load key word

        li        $T1, 0
        aes32esi  $T1, $T1, $T0, 0          // Sub Word Forward
        aes32esi  $T1, $T1, $T0, 1 
        aes32esi  $T1, $T1, $T0, 2
        aes32esi  $T1, $T1, $T0, 3

        li        $T0, 0
        aes32dsmi $T0, $T0, $T1, 0          // Sub Word Inverse & Inverse MixColumns
        aes32dsmi $T0, $T0, $T1, 1
        aes32dsmi $T0, $T0, $T1, 2
        aes32dsmi $T0, $T0, $T1, 3

        sw   $T0, 0($RKP)             // Store key word.

        addi $RKP, $RKP, 4            // Increment round key pointer
        bne  $RKP, $RKE, .dec_ks_loop_192 // Finished yet?

    lw      ra, 0(sp)
    addi    sp, sp,  16

    ret
.endfunc
___

$C0="a2";
$C1="a3";
$C2="a4";
$C3="a5";
$C4="a7";
$C5="t5";
$C6="t6";
$C7="t2";

$RK="a0";
$RKP="a6";
$CK="a1";

$RKE="t0";
$RCP="t1";
$RCT="t4";

$T1="t3";
$T2="t4";


$code.=<<___;

.text


.func     aes_256_set_encrypt_key
.global   aes_256_set_encrypt_key
aes_256_set_encrypt_key:       // a0 - uint32_t rk [AES_256_RK_WORDS]
                                // a1 - uint8_t  ck [AES_256_CK_BYTE ]

    lw  $C0,  0($CK)
    lw  $C1,  4($CK)
    lw  $C2,  8($CK)
    lw  $C3, 12($CK)
    lw  $C4, 16($CK)
    lw  $C5, 20($CK)
    lw  $C6, 24($CK)
    lw  $C7, 28($CK)
    
    mv      $RKP, $RK
    addi    $RKE, $RK, 56*4       //
    la      $RCP, aes_round_const//="t1";= round constant pointer
    
    sw      $C0,  0($RKP)         // rkp[0]
    sw      $C1,  4($RKP)         // rkp[1]
    sw      $C2,  8($RKP)         // rkp[2]
    sw      $C3, 12($RKP)         // rkp[3]

.aes_256_enc_ks_l0:             // Loop start

    sw      $C4, 16($RKP)         // rkp[4]
    sw      $C5, 20($RKP)         // rkp[5]
    sw      $C6, 24($RKP)         // rkp[6]
    sw      $C7, 28($RKP)         // rkp[7]

    addi    $RKP, $RKP, 32        // increment rkp


    lbu     $RCT, 0($RCP)         // Load round constant byte
    addi    $RCP, $RCP, 1         // Increment round constant byte
    xor     $C0, $C0, $RCT         // c0 ^= rcp
                                
    ROR32I $T1, $T2, $C7, 8        // tr= ROR32(c3, 8)
    aes32esi $C0, $C0, $T1, 0   // tr= sbox(tr)
    aes32esi $C0, $C0, $T1, 1   //
    aes32esi $C0, $C0, $T1, 2   //
    aes32esi $C0, $C0, $T1, 3   //
    
    xor     $C1, $C1, $C0          // C1 ^= C0
    xor     $C2, $C2, $C1          // C2 ^= C1
    xor     $C3, $C3, $C2          // C3 ^= C2
    
    sw      $C0,  0($RKP)         // rkp[0]
    sw      $C1,  4($RKP)         // rkp[1]
    sw      $C2,  8($RKP)         // rkp[2]
    sw      $C3, 12($RKP)         // rkp[3]
    
    beq     $RKE, $RKP, .aes_256_enc_ks_finish
    
    aes32esi $C4, $C4, $C3, 0   // tr= sbox(tr)
    aes32esi $C4, $C4, $C3, 1   //
    aes32esi $C4, $C4, $C3, 2   //
    aes32esi $C4, $C4, $C3, 3   //

    xor     $C5, $C5, $C4          // C5 ^= C4
    xor     $C6, $C6, $C5          // C6 ^= C5
    xor     $C7, $C7, $C6          // C7 ^= C6

    j .aes_256_enc_ks_l0        // Loop continue

.aes_256_enc_ks_finish:
    ret

.endfunc
___

$RK="a0";
$RKP="a2";
$RKE="a3";
$T0="t0";
$T1="t1";

$code.=<<___;
.func     aes_256_set_decrypt_key
.global   aes_256_set_decrypt_key
aes_256_set_decrypt_key:           // a0 - uint32_t rk [AES_256_RK_WORDS]
                                    // a1 - uint8_t  ck [AES_256_CK_BYTE ]
   
    addi    sp, sp, -16              // Save stack
    sw      ra, 0(sp)

    call    aes_256_set_encrypt_key //

    addi    $RKP, $RK, 16              // a0= &rk[ 4]
    addi    $RKE, $RK, 56*4            // a1= &rk[40]

    .dec_ks_loop_256:
        
        lw   $T0, 0($RKP)              // Load key word

        li        $T1, 0
        aes32esi  $T1, $T1, $T0, 0          // Sub Word Forward
        aes32esi  $T1, $T1, $T0, 1 
        aes32esi  $T1, $T1, $T0, 2
        aes32esi  $T1, $T1, $T0, 3

        li        $T0, 0
        aes32dsmi $T0, $T0, $T1, 0          // Sub Word Inverse & Inverse MixColumns
        aes32dsmi $T0, $T0, $T1, 1
        aes32dsmi $T0, $T0, $T1, 2
        aes32dsmi $T0, $T0, $T1, 3

        sw   $T0, 0($RKP)             // Store key word.

        addi $RKP, $RKP, 4            // Increment round key pointer
        bne  $RKP, $RKE, .dec_ks_loop_256 // Finished yet?

    lw      ra, 0(sp)
    addi    sp, sp,  16

    ret
    
.endfunc
___

$T0="a4";
$T1="a5";
$T2="a6";
$T3="a7";
$U0="t0";
$U1="t1";
$U2="t2";
$U3="t3";
$CT="a1";
$PT="a0";
$RK="a2";
$KP="a3";

$code.=<<___;

.func   aes_ecb_encrypt                         // a1 - uint8_t     ct [16],
                                                // a0 - uint8_t     pt [16],
aes_ecb_encrypt:                                //="a2"; - uint32_t  * rk,

    AES_LOAD_STATE $T0,$T1,$T2,$T3,$PT,$U0,$U1,$U2,$U3   // Columns in $T*

    lw      $U0,  0($RK)                          // Load Round Key
    lw      $U1,  4($RK)
    lw      $U2,  8($RK)
    lw      $U3, 12($RK)

    xor     $T0, $T0, $U0                          // Add Round Key
    xor     $T1, $T1, $U1
    xor     $T2, $T2, $U2
    xor     $T3, $T3, $U3

.aes_enc_block_l0:
    
        lw      $U0, 16($RK)                      // Load Round Key
        lw      $U1, 20($RK)
        lw      $U2, 24($RK)
        lw      $U3, 28($RK)

        aes32esmi   $U0, $U0, $T0, 0                   // Even Round
        aes32esmi   $U0, $U0, $T1, 1
        aes32esmi   $U0, $U0, $T2, 2
        aes32esmi   $U0, $U0, $T3, 3
                             
        aes32esmi   $U1, $U1, $T1, 0
        aes32esmi   $U1, $U1, $T2, 1
        aes32esmi   $U1, $U1, $T3, 2
        aes32esmi   $U1, $U1, $T0, 3
                             
        aes32esmi   $U2, $U2, $T2, 0
        aes32esmi   $U2, $U2, $T3, 1
        aes32esmi   $U2, $U2, $T0, 2
        aes32esmi   $U2, $U2, $T1, 3
                             
        aes32esmi   $U3, $U3, $T3, 0
        aes32esmi   $U3, $U3, $T0, 1
        aes32esmi   $U3, $U3, $T1, 2
        aes32esmi   $U3, $U3, $T2, 3                   // U* contains new state

        lw      $T0, 32($RK)                      // Load Round Key
        lw      $T1, 36($RK)
        lw      $T2, 40($RK)
        lw      $T3, 44($RK)

        addi    $RK, $RK, 32                      // Step Key pointer
        beq     $RK, $KP, .aes_enc_block_l_finish // Break from loop
        
        aes32esmi   $T0, $T0, $U0, 0                   // Odd Round
        aes32esmi   $T0, $T0, $U1, 1
        aes32esmi   $T0, $T0, $U2, 2
        aes32esmi   $T0, $T0, $U3, 3
                             
        aes32esmi   $T1, $T1, $U1, 0
        aes32esmi   $T1, $T1, $U2, 1
        aes32esmi   $T1, $T1, $U3, 2
        aes32esmi   $T1, $T1, $U0, 3
                             
        aes32esmi   $T2, $T2, $U2, 0
        aes32esmi   $T2, $T2, $U3, 1
        aes32esmi   $T2, $T2, $U0, 2
        aes32esmi   $T2, $T2, $U1, 3
                             
        aes32esmi   $T3, $T3, $U3, 0
        aes32esmi   $T3, $T3, $U0, 1
        aes32esmi   $T3, $T3, $U1, 2
        aes32esmi   $T3, $T3, $U2, 3                   // $T* contains new state

    j .aes_enc_block_l0                         // repeat loop

.aes_enc_block_l_finish:
    
    aes32esi    $T0, $T0, $U0, 0                       // Final round. No MixColumn.
    aes32esi    $T0, $T0, $U1, 1
    aes32esi    $T0, $T0, $U2, 2
    aes32esi    $T0, $T0, $U3, 3
                         
    aes32esi    $T1, $T1, $U1, 0
    aes32esi    $T1, $T1, $U2, 1
    aes32esi    $T1, $T1, $U3, 2
    aes32esi    $T1, $T1, $U0, 3
                         
    aes32esi    $T2, $T2, $U2, 0
    aes32esi    $T2, $T2, $U3, 1
    aes32esi    $T2, $T2, $U0, 2
    aes32esi    $T2, $T2, $U1, 3
                         
    aes32esi    $T3, $T3, $U3, 0
    aes32esi    $T3, $T3, $U0, 1
    aes32esi    $T3, $T3, $U1, 2
    aes32esi    $T3, $T3, $U2, 3                       // $T* contains new state

    AES_DUMP_STATE  $T0, $T1, $T2, $T3, $CT

    ret

.endfunc

.func   aes_128_ecb_encrypt                     // a1 - uint8_t     ct [16],
.global aes_128_ecb_encrypt                     // a0 - uint8_t     pt [16],
aes_128_ecb_encrypt:                            //="a2"; - uint32_t  * rk,
    addi    $KP, $RK, 16*10                       // kp= rk + 4*nr
    j       aes_ecb_encrypt
.endfunc

.func   aes_192_ecb_encrypt                     // a1 - uint8_t     ct [16],
.global aes_192_ecb_encrypt                     // a0 - uint8_t     pt [16],
aes_192_ecb_encrypt:                            //="a2"; - uint32_t  * rk,
    addi    $KP, $RK, 16*12                       // kp= rk + 4*nr
    j       aes_ecb_encrypt
.endfunc

.func   aes_256_ecb_encrypt                     // a1 - uint8_t     ct [16],
.global aes_256_ecb_encrypt                     // a0 - uint8_t     pt [16],
aes_256_ecb_encrypt:                            //="a2"; - uint32_t  * rk,
    addi    $KP, $RK, 16*14                       // kp= rk + 4*nr
    j       aes_ecb_encrypt
.endfunc
___


$T0="a4";
$T1="a5";
$T2="a6";
$T3="a7";
$U0="t0";
$U1="t1";
$U2="t2";
$U3="t3";
$CT="a0";
$PT="a1";
$RK="a2";
$KP="a3";

$code.=<<___;

.func   aes_ecb_decrypt                         // a1 - uint8_t     pt [16],
                                                // a0 - uint8_t     ct [16],
aes_ecb_decrypt:                                // a2 - uint32_t  * rk,

    AES_LOAD_STATE $T0,$T1,$T2,$T3,$CT,$U0,$U1,$U2,$U3   // Columns in T*

    lw      $U0,  0($KP)                          // Load Round Key
    lw      $U1,  4($KP)
    lw      $U2,  8($KP)
    lw      $U3, 12($KP)

    xor     $T0, $T0, $U0                          // Add Round Key
    xor     $T1, $T1, $U1
    xor     $T2, $T2, $U2
    xor     $T3, $T3, $U3

    addi    $KP, $KP, -32                         // Loop counter

.aes_dec_block_l0:
    
        lw      $U0, 16($KP)                      // Load Round Key
        lw      $U1, 20($KP)
        lw      $U2, 24($KP)
        lw      $U3, 28($KP)

        aes32dsmi  $U0, $U0, $T0, 0                    // Even Round
        aes32dsmi  $U0, $U0, $T3, 1
        aes32dsmi  $U0, $U0, $T2, 2
        aes32dsmi  $U0, $U0, $T1, 3

        aes32dsmi  $U1, $U1, $T1, 0
        aes32dsmi  $U1, $U1, $T0, 1
        aes32dsmi  $U1, $U1, $T3, 2
        aes32dsmi  $U1, $U1, $T2, 3

        aes32dsmi  $U2, $U2, $T2, 0
        aes32dsmi  $U2, $U2, $T1, 1
        aes32dsmi  $U2, $U2, $T0, 2
        aes32dsmi  $U2, $U2, $T3, 3

        aes32dsmi  $U3, $U3, $T3, 0
        aes32dsmi  $U3, $U3, $T2, 1
        aes32dsmi  $U3, $U3, $T1, 2
        aes32dsmi  $U3, $U3, $T0, 3                    // U* contains new state

        lw      $T0,  0($KP)                      // Load Round Key
        lw      $T1,  4($KP)
        lw      $T2,  8($KP)
        lw      $T3, 12($KP)

        beq     $RK, $KP, .aes_dec_block_l_finish // Break from loop
        addi    $KP, $KP, -32                     // Step Key pointer
        
        aes32dsmi  $T0, $T0, $U0, 0                    // Odd Round
        aes32dsmi  $T0, $T0, $U3, 1
        aes32dsmi  $T0, $T0, $U2, 2
        aes32dsmi  $T0, $T0, $U1, 3

        aes32dsmi  $T1, $T1, $U1, 0
        aes32dsmi  $T1, $T1, $U0, 1
        aes32dsmi  $T1, $T1, $U3, 2
        aes32dsmi  $T1, $T1, $U2, 3

        aes32dsmi  $T2, $T2, $U2, 0
        aes32dsmi  $T2, $T2, $U1, 1
        aes32dsmi  $T2, $T2, $U0, 2
        aes32dsmi  $T2, $T2, $U3, 3

        aes32dsmi  $T3, $T3, $U3, 0
        aes32dsmi  $T3, $T3, $U2, 1
        aes32dsmi  $T3, $T3, $U1, 2
        aes32dsmi  $T3, $T3, $U0, 3                    // T* contains new state

    j .aes_dec_block_l0                         // repeat loop

.aes_dec_block_l_finish:
    
    aes32dsi    $T0, $T0, $U0, 0                       // Final round, no MixColumns
    aes32dsi    $T0, $T0, $U3, 1
    aes32dsi    $T0, $T0, $U2, 2
    aes32dsi    $T0, $T0, $U1, 3

    aes32dsi    $T1, $T1, $U1, 0
    aes32dsi    $T1, $T1, $U0, 1
    aes32dsi    $T1, $T1, $U3, 2
    aes32dsi    $T1, $T1, $U2, 3

    aes32dsi    $T2, $T2, $U2, 0
    aes32dsi    $T2, $T2, $U1, 1
    aes32dsi    $T2, $T2, $U0, 2
    aes32dsi    $T2, $T2, $U3, 3

    aes32dsi    $T3, $T3, $U3, 0
    aes32dsi    $T3, $T3, $U2, 1
    aes32dsi    $T3, $T3, $U1, 2
    aes32dsi    $T3, $T3, $U0, 3                       // T* contains new state

    AES_DUMP_STATE  $T0, $T1, $T2, $T3, $PT

    ret

.endfunc

.func   aes_128_ecb_decrypt                     // a1 - uint8_t     ct [16],
.global aes_128_ecb_decrypt                     // a0 - uint8_t     pt [16],
aes_128_ecb_decrypt:                            // a2 - uint32_t  * rk,
    addi    $KP, $RK, 16*10                       // kp = rk + 4*nr
    j       aes_ecb_decrypt
.endfunc

.func   aes_192_ecb_decrypt                     // a1 - uint8_t     ct [16],
.global aes_192_ecb_decrypt                     // a0 - uint8_t     pt [16],
aes_192_ecb_decrypt:                            // a2 - uint32_t  * rk,
    addi    $KP, $RK, 16*12                       // kp = rk + 4*nr
    j       aes_ecb_decrypt
.endfunc

.func   aes_256_ecb_decrypt                     // a1 - uint8_t     ct [16],
.global aes_256_ecb_decrypt                     // a0 - uint8_t     pt [16],
aes_256_ecb_decrypt:                            // a2 - uint32_t  * rk,
    addi    $KP, $RK, 16*14                       // kp = rk + 4*nr
    j       aes_ecb_decrypt
.endfunc
___

print $code;
close STDOUT or die "error closing STDOUT: $!";    # enforce flush
