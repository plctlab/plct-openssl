#! /usr/bin/env perl
# Copyright 2007-2020 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the ";License";).  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html



# AES for riscv64.

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
// Load the byte-aligned AES state from pointer in CK
// - Each column is loaded into the T* registers.
// - The X* registers are temps.
//
.macro AES_LOAD_STATE T0, T1, CK, X0, X1

#if ((AES_BYTE_ALIGNED == 1) || (defined(AES_BYTE_ALIGNED)))

    lbu     T0,  7(\\CK)
    lbu     \\T1, 15(\\CK)
    lbu     \\X0,  6(\\CK)
    lbu     \\X1, 14(\\CK)
    slli    \\T0, \\T0, 8
    slli    \\T1, \\T1, 8
    or      \\T0, \\T0, \\X0
    or      \\T1, \\T1, \\X1
    lbu     \\X0,  5(\\CK)
    lbu     \\X1, 13(\\CK)
    slli    \\T0, \\T0, 8
    slli    \\T1, \\T1, 8
    or      \\T0, \\T0, \\X0
    or      \\T1, \\T1, \\X1
    lbu     \\X0,  4(\\CK)
    lbu     \\X1, 12(\\CK)
    slli    \\T0, \\T0, 8
    slli    \\T1, \\T1, 8
    or      \\T0, \\T0, \\X0
    or      \\T1, \\T1, \\X1
    lbu     \\X0,  3(\\CK)
    lbu     \\X1, 11(\\CK)
    slli    \\T0, \\T0, 8
    slli    \\T1, \\T1, 8
    or      \\T0, \\T0, \\X0
    or      \\T1, \\T1, \\X1
    lbu     \\X0,  2(\\CK)
    lbu     \\X1, 10(\\CK)
    slli    \\T0, \\T0, 8
    slli    \\T1, \\T1, 8
    or      \\T0, \\T0, \\X0
    or      \\T1, \\T1, \\X1
    lbu     \\X0,  1(\\CK)
    lbu     \\X1,  9(\\CK)
    slli    \\T0, \\T0, 8
    slli    \\T1, \\T1, 8
    or      \\T0, \\T0, \\X0
    or      \\T1, \\T1, \\X1
    lbu     \\X0,  0(\\CK)
    lbu     \\X1,  8(\\CK)
    slli    \\T0, \\T0, 8
    slli    \\T1, \\T1, 8
    or      \\T0, \\T0, \\X0
    or      \\T1, \\T1, \\X1

#else

    ld      \\T0, 0(\\CK)
    ld      \\T1, 8(\\CK)

#endif

.endm

//
// Dump the AES state from column-wise registers into a byte-aligned array.
//
.macro AES_DUMP_STATE T0, T1, CT, X0, X1, OFFSET

#if ((AES_BYTE_ALIGNED == 1) || (defined(AES_BYTE_ALIGNED)))

    sw      \\T0, (\\OFFSET + 0)(\\CT)
    sw      \\T1, (\\OFFSET + 8)(\\CT)
    srli    \\X0, \\T0, 32
    srli    \\X1, \\T1, 32
    sw      \\X0, (\\OFFSET + 4)(\\CT)
    sw      \\X1, (\\OFFSET +12)(\\CT)

#else

    sd      \\T0, (\\OFFSET + 0)(\\CT)
    sd      \\T1, (\\OFFSET + 8)(\\CT)
    
#endif

.endm

.macro AES_128_KEY_ROUND RK_LO, RK_HI, RK, TMP1, TMP2, OFFSET, RCON
    aes64ks1i     \\TMP1 , \\RK_HI, \\RCON
    aes64ks2      \\RK_LO, \\TMP1 , \\RK_LO
    aes64ks2      \\RK_HI, \\RK_LO, \\RK_HI
    AES_DUMP_STATE  \\RK_LO, \\RK_HI, \\RK   , \\TMP1, \\TMP2, \\OFFSET
.endm

//
// Computes 1.5 round keys per invocation.
.macro AES_192_KEY_ROUND RK0, RK1, RK2, T0, RKP, I
    sd          \\RK0, ( 0+(24*\\I))(\\RKP)
    sd          \\RK1, ( 8+(24*\\I))(\\RKP)
    sd          \\RK2, (16+(24*\\I))(\\RKP)
    aes64ks1i \\T0 , \\RK2 , \\I
    aes64ks2  \\RK0, \\T0  , \\RK0
    aes64ks2  \\RK1, \\RK0 , \\RK1
    aes64ks2  \\RK2, \\RK1 , \\RK2
.endm

//
// Computes 2 round keys per invocation.
.macro AES_256_KEY_ROUND RK0, RK1, RK2, RK3, T0, RKP, I
    sd  \\RK0, ( 0+(\\I*32))(\\RKP)
    sd  \\RK1, ( 8+(\\I*32))(\\RKP)
    sd  \\RK2, (16+(\\I*32))(\\RKP)
    sd  \\RK3, (24+(\\I*32))(\\RKP)
    aes64ks1i \\T0 , \\RK3 , \\I
    aes64ks2  \\RK0, \\T0  , \\RK0
    aes64ks2  \\RK1, \\RK0 , \\RK1
    aes64ks1i \\T0 , \\RK1 , 0xA
    aes64ks2  \\RK2, \\T0  , \\RK2
    aes64ks2  \\RK3, \\RK2 , \\RK3
.endm

.macro DOUBLE_ROUND_ENC RK, K0, K1, K2, K3, S0, S1, N0, N1, OFFSET
    ld          \\K0, (\\OFFSET + 0)(\\RK)      // Load round keys in
    ld          \\K1, (\\OFFSET + 8)(\\RK)      // batches of 4 double words
    ld          \\K2, (\\OFFSET +16)(\\RK)
    ld          \\K3, (\\OFFSET +24)(\\RK)
    xor         \\S0, \\S0, \\K0                // AddRoundKey
    xor         \\S1, \\S1, \\K1
    aes64esm    \\N0, \\S0, \\S1                // Rest of round
    aes64esm    \\N1, \\S1, \\S0
    xor         \\N0, \\N0, \\K2                // AddRoundKey
    xor         \\N1, \\N1, \\K3
    aes64esm   \\S0, \\N0, \\N1                // Rest of round
    aes64esm   \\S1, \\N1, \\N0
.endm

.macro LAST_2ROUNDS_ENC RK, K0, K1, K2, K3, S0, S1, N0, N1, OFFSET
    ld          \\K0, (\\OFFSET + 0)(\\RK)      // Load two round keys
    ld          \\K1, (\\OFFSET + 8)(\\RK)
    ld          \\K2, (\\OFFSET +16)(\\RK)
    ld          \\K3, (\\OFFSET +24)(\\RK)
    xor         \\S0, \\S0, \\K0                // AddRoundKey
    xor         \\S1, \\S1, \\K1
    ld          \\K0, (\\OFFSET +32)(\\RK)      // Load final round key
    ld          \\K1, (\\OFFSET +40)(\\RK)
    aes64esm    \\N0, \\S0, \\S1                // Rest of round: Shift,
    aes64esm    \\N1, \\S1, \\S0                // Sub, Mix
    xor         \\N0, \\N0, \\K2                // AddRoundKey
    xor         \\N1, \\N1, \\K3
    aes64es     \\S0, \\N0, \\N1                // Final round: Shift, Sub
    aes64es     \\S1, \\N1, \\N0
    xor         \\S0, \\S0, \\K0                // Final AddRoundKey
    xor         \\S1, \\S1, \\K1
.endm

.macro DOUBLE_ROUND_DEC RK, K0, K1, K2, K3, S0, S1, N0, N1, OFFSET
    ld          \\K0, \\OFFSET +16(\\RK)      // Load two roundkeys in a
    ld          \\K1, \\OFFSET +24(\\RK)      // batch
    ld          \\K2, \\OFFSET + 0(\\RK)
    ld          \\K3, \\OFFSET + 8(\\RK)
    aes64dsm    \\N0, \\S0, \\S1              // InvShiftRows, InvSubBytes
    aes64dsm    \\N1, \\S1, \\S0              // InvMixColumns
    xor         \\S0, \\N0, \\K0              // Add Round Key
    xor         \\S1, \\N1, \\K1
    aes64dsm    \\N0, \\S0, \\S1              // InvShiftRows, InvSubBytes
    aes64dsm    \\N1, \\S1, \\S0              // InvMixColumns
    xor         \\S0, \\N0, \\K2              // AddRoundKey
    xor         \\S1, \\N1, \\K3
.endm

.macro LAST_2ROUNDS_DEC RK, K0, K1, K2, K3, S0, S1, N0, N1, OFFSET
    ld          \\K0,\\OFFSET +16(\\RK)       // Load two round keys
    ld          \\K1,\\OFFSET +24(\\RK)
    ld          \\K2,\\OFFSET + 0(\\RK)
    ld          \\K3,\\OFFSET + 8(\\RK)
    aes64dsm    \\N0, \\S0, \\S1              // InvShiftRows, InvSubBytes
    aes64dsm    \\N1, \\S1, \\S0              // InvMixColumns
    xor         \\S0, \\N0, \\K0              // Add Round Key
    xor         \\S1, \\N1, \\K1
    aes64ds     \\N0, \\S0, \\S1              // InvShiftRows, InvSubBytes
    aes64ds     \\N1, \\S1, \\S0
    xor         \\S0, \\N0, \\K2              // Final AddRoundKey
    xor         \\S1, \\N1, \\K3
.endm
___

$RK="a0";
$CK="a1";

$TMP1="t0";
$TMP2="t1";
$TMP3="t2";

$RK_LO="a2";
$RK_HI="a3";

$code.=<<___;
.func     aes_128_set_encrypt_key
.global   aes_128_set_encrypt_key
aes_128_set_encrypt_key:       // a0 - uint32_t rk [AES_128_$RK_WORDS]
                                // a1 - uint8_t  ck [AES_128_$CK_BYTE ]

   // See aes_common.S for load/dump_state macros
    AES_LOAD_STATE  $RK_LO, $RK_HI, $CK, $TMP1, $TMP2

    AES_DUMP_STATE  $RK_LO, $RK_HI, $RK, $TMP1, $TMP2, 0*16

    AES_128_KEY_ROUND   $RK_LO, $RK_HI, $RK, $TMP1, $TMP2, 1*16, 0
    AES_128_KEY_ROUND   $RK_LO, $RK_HI, $RK, $TMP1, $TMP2, 2*16, 1
    AES_128_KEY_ROUND   $RK_LO, $RK_HI, $RK, $TMP1, $TMP2, 3*16, 2
    AES_128_KEY_ROUND   $RK_LO, $RK_HI, $RK, $TMP1, $TMP2, 4*16, 3
    AES_128_KEY_ROUND   $RK_LO, $RK_HI, $RK, $TMP1, $TMP2, 5*16, 4
    AES_128_KEY_ROUND   $RK_LO, $RK_HI, $RK, $TMP1, $TMP2, 6*16, 5
    AES_128_KEY_ROUND   $RK_LO, $RK_HI, $RK, $TMP1, $TMP2, 7*16, 6
    AES_128_KEY_ROUND   $RK_LO, $RK_HI, $RK, $TMP1, $TMP2, 8*16, 7
    AES_128_KEY_ROUND   $RK_LO, $RK_HI, $RK, $TMP1, $TMP2, 9*16, 8
    AES_128_KEY_ROUND   $RK_LO, $RK_HI, $RK, $TMP1, $TMP2,10*16, 9

    ret  
.endfunc
___

$RKP="t0";
$RKE="t1";

$code.=<<___;
.global aes_ks_dec_invmc
.func   aes_ks_dec_invmc
aes_ks_dec_invmc:           // a0 - uint64_t * ks
                            // a1 - uint64_t * end_ptr

    .l0:
        ld          a2, 0(a0)
        ld          a3, 8(a0)
        
        aes64im a2, a2
        aes64im a3, a3

        sd          a2, 0(a0)
        sd          a3, 8(a0)

        addi        a0, a0, 16
        bne         a0, a1, .l0

    ret

.endfunc

.func     aes_128_set_decrypt_key
.global   aes_128_set_decrypt_key
aes_128_set_decrypt_key:           // a0 - uint32_t rk [AES_128_$RK_WORDS]
                                    // a1 - uint8_t  ck [AES_128_$CK_BYTE ]

    addi sp, sp, -32
    sd   ra, 0(sp)
    sd   a0, 8(sp)
    sd   a1,16(sp)

    call aes_128_set_encrypt_key

    addi a0, a0, 16
    addi a1, a0, 8*(44/2-4)

    call aes_ks_dec_invmc
        
    ld   ra, 0(sp)
    ld   a0, 8(sp)
    ld   a1,16(sp)
    addi sp, sp, 32
    
    ret
.endfunc
___


$RKP="a0";
$CKP="a1";
$T0="t0";

$RT0="a2";
$RT1="a3";
$RK2="a4";

$code.=<<___;


.func     aes_192_set_encrypt_key
.global   aes_192_set_encrypt_key
aes_192_set_encrypt_key:       // a0 - uint32_t rk [AES_192_$RK_WORDS]
                                // a1 - uint8_t  ck [AES_192_$CK_BYTE ]

    ld  $RT0,  0($CKP)            // Load initial round/cipher key
    ld  $RT1,  8($CKP)
    ld  $RK2, 16($CKP)

    AES_192_KEY_ROUND $RT0, $RT1, $RK2, $T0, $RKP, 0
    AES_192_KEY_ROUND $RT0, $RT1, $RK2, $T0, $RKP, 1
    AES_192_KEY_ROUND $RT0, $RT1, $RK2, $T0, $RKP, 2
    AES_192_KEY_ROUND $RT0, $RT1, $RK2, $T0, $RKP, 3
    AES_192_KEY_ROUND $RT0, $RT1, $RK2, $T0, $RKP, 4
    AES_192_KEY_ROUND $RT0, $RT1, $RK2, $T0, $RKP, 5
    AES_192_KEY_ROUND $RT0, $RT1, $RK2, $T0, $RKP, 6

    sd  $RT0, ( 0+(24*7))($RKP)
    sd  $RT1, ( 8+(24*7))($RKP)
    sd  $RK2, (16+(24*7))($RKP)
    
    aes64ks1i $T0 , $RK2 , 7
    aes64ks2  $RT0, $T0  , $RT0
    aes64ks2  $RT1, $RT0 , $RT1
    
    sd  $RT0, ( 0+(24*8))($RKP)
    sd  $RT1, ( 8+(24*8))($RKP)

    ret

.endfunc
___

$RKP="t0";
$RKE="t1";

$code.=<<___;
.func     aes_192_set_decrypt_key
.global   aes_192_set_decrypt_key
aes_192_set_decrypt_key:           // a0 - uint32_t rk [AES_192_$RK_WORDS]
                                    // a1 - uint8_t  ck [AES_192_$CK_BYTE ]
   
    addi sp, sp, -32
    sd   ra, 0(sp)
    sd   a0, 8(sp)
    sd   a1,16(sp)

    call aes_192_set_encrypt_key

    addi a0, a0, 16
    addi a1, a0, 8*(52/2-4)

    call aes_ks_dec_invmc
        
    ld   ra, 0(sp)
    ld   a0, 8(sp)
    ld   a1,16(sp)
    addi sp, sp, 32
    
    ret
.endfunc
___

$RKP="a0";
$CKP="a1";
$T0="t0";

$RT0="a2";
$RT1="a3";
$RK2="a4";
$RK3="a5";

$code.=<<___;
.func     aes_256_set_encrypt_key
.global   aes_256_set_encrypt_key
aes_256_set_encrypt_key:       // a0 - uint32_t rk [AES_256_$RK_WORDS]
                                // a1 - uint8_t  ck [AES_256_$CK_BYTE ]

    ld  $RT0,  0($CKP)            // Load initial round/cipher key
    ld  $RT1,  8($CKP)
    ld  $RK2, 16($CKP)
    ld  $RK3, 24($CKP)

    AES_256_KEY_ROUND $RT0, $RT1, $RK2, $RK3, $T0, $RKP, 0
    AES_256_KEY_ROUND $RT0, $RT1, $RK2, $RK3, $T0, $RKP, 1
    AES_256_KEY_ROUND $RT0, $RT1, $RK2, $RK3, $T0, $RKP, 2
    AES_256_KEY_ROUND $RT0, $RT1, $RK2, $RK3, $T0, $RKP, 3
    AES_256_KEY_ROUND $RT0, $RT1, $RK2, $RK3, $T0, $RKP, 4
    AES_256_KEY_ROUND $RT0, $RT1, $RK2, $RK3, $T0, $RKP, 5
    
    sd  $RT0, ( 0+(6*32))($RKP)
    sd  $RT1, ( 8+(6*32))($RKP)
    sd  $RK2, (16+(6*32))($RKP)
    sd  $RK3, (24+(6*32))($RKP)
    
    aes64ks1i $T0 , $RK3 , 6
    aes64ks2  $RT0, $T0  , $RT0
    aes64ks2  $RT1, $RT0 , $RT1
    
    sd  $RT0, ( 0+(7*32))($RKP)
    sd  $RT1, ( 8+(7*32))($RKP)

    ret


.endfunc
___

$RKP="t0";
$RKE="t1";

$code.=<<___;
.func     aes_256_set_decrypt_key
.global   aes_256_set_decrypt_key
aes_256_set_decrypt_key:           // a0 - uint32_t rk [AES_256_$RK_WORDS]
                                    // a1 - uint8_t  ck [AES_256_$CK_BYTE ]
   
    addi sp, sp, -32
    sd   ra, 0(sp)
    sd   a0, 8(sp)
    sd   a1,16(sp)

    call aes_256_set_encrypt_key

    addi a0, a0, 16
    addi a1, a0, 8*(60/2-4)

    call aes_ks_dec_invmc
        
    ld   ra, 0(sp)
    ld   a0, 8(sp)
    ld   a1,16(sp)
    addi sp, sp, 32
    
    ret
    
.endfunc
___

$T0="t0";
$T1="t1";
$K0="t2";
$K1="t3";
$CT="a1";
$PT="a0";
$RK="a2";
$NR="a3";
$S0="a5";
$S1="a6";
$N0="a7";
$N1="t5";

$code.=<<___;
//
// AES 128 Encrypt
//

.func   aes_128_ecb_encrypt                    // a1 - uint8_t     ct [16],
.global aes_128_ecb_encrypt                    // a0 - uint8_t     pt [16],
aes_128_ecb_encrypt:                           // a2 - uint32_t  * rk,

    AES_LOAD_STATE $S0, $S1, $PT, $T0, $T1       // Load plaintext

    DOUBLE_ROUND_ENC   $RK, $K0, $K1, $T0, $T1, $S0, $S1, $N0, $N1, 0*32
    DOUBLE_ROUND_ENC   $RK, $K0, $K1, $T0, $T1, $S0, $S1, $N0, $N1, 1*32
    DOUBLE_ROUND_ENC   $RK, $K0, $K1, $T0, $T1, $S0, $S1, $N0, $N1, 2*32
    DOUBLE_ROUND_ENC   $RK, $K0, $K1, $T0, $T1, $S0, $S1, $N0, $N1, 3*32
    LAST_2ROUNDS_ENC   $RK, $K0, $K1, $T0, $T1, $S0, $S1, $N0, $N1, 4*32

    AES_DUMP_STATE $S0, $S1, $CT, $T0, $T1, 0    // Save ciphertext

    ret
.endfunc


//
// AES 192 Encrypt
//

.func   aes_192_ecb_encrypt                    // a1 - uint8_t     ct [16],
.global aes_192_ecb_encrypt                    // a0 - uint8_t     pt [16],
aes_192_ecb_encrypt:                           // a2 - uint32_t  * rk,

    AES_LOAD_STATE $S0, $S1, $PT, $T0, $T1       // Load plaintext

    DOUBLE_ROUND_ENC   $RK, $K0, $K1, $T0, $T1, $S0, $S1, $N0, $N1, 0*32
    DOUBLE_ROUND_ENC   $RK, $K0, $K1, $T0, $T1, $S0, $S1, $N0, $N1, 1*32
    DOUBLE_ROUND_ENC   $RK, $K0, $K1, $T0, $T1, $S0, $S1, $N0, $N1, 2*32
    DOUBLE_ROUND_ENC   $RK, $K0, $K1, $T0, $T1, $S0, $S1, $N0, $N1, 3*32
    DOUBLE_ROUND_ENC   $RK, $K0, $K1, $T0, $T1, $S0, $S1, $N0, $N1, 4*32
    LAST_2ROUNDS_ENC   $RK, $K0, $K1, $T0, $T1, $S0, $S1, $N0, $N1, 5*32

    AES_DUMP_STATE $S0, $S1, $CT, $T0, $T1, 0    // Save ciphertext

    ret
.endfunc

//
// AES 256 Encrypt
//

.func   aes_256_ecb_encrypt                    // a1 - uint8_t     ct [16],
.global aes_256_ecb_encrypt                    // a0 - uint8_t     pt [16],
aes_256_ecb_encrypt:                           // a2 - uint32_t  * rk,

    AES_LOAD_STATE $S0, $S1, $PT, $T0, $T1       // Load plaintext

    DOUBLE_ROUND_ENC   $RK, $K0, $K1, $T0, $T1, $S0, $S1, $N0, $N1, 0*32
    DOUBLE_ROUND_ENC   $RK, $K0, $K1, $T0, $T1, $S0, $S1, $N0, $N1, 1*32
    DOUBLE_ROUND_ENC   $RK, $K0, $K1, $T0, $T1, $S0, $S1, $N0, $N1, 2*32
    DOUBLE_ROUND_ENC   $RK, $K0, $K1, $T0, $T1, $S0, $S1, $N0, $N1, 3*32
    DOUBLE_ROUND_ENC   $RK, $K0, $K1, $T0, $T1, $S0, $S1, $N0, $N1, 4*32
    DOUBLE_ROUND_ENC   $RK, $K0, $K1, $T0, $T1, $S0, $S1, $N0, $N1, 5*32
    LAST_2ROUNDS_ENC   $RK, $K0, $K1, $T0, $T1, $S0, $S1, $N0, $N1, 6*32

    AES_DUMP_STATE $S0, $S1, $CT, $T0, $T1, 0    // Save ciphertext

    ret
.endfunc
___


$T0="t0";
$T1="t1";
$K0="t2";
$K1="t3";
$CT="a0";
$PT="a1";
$RK="a2";
$NR="a3";
$S0="a5";
$S1="a6";
$N0="a7";
$N1="t6";

$code.=<<___;
//
// AES 128 Decrypt
//

.func   aes_128_ecb_decrypt                    // a1 - uint8_t     pt [16],
.global aes_128_ecb_decrypt                    // a0 - uint8_t     ct [16],
aes_128_ecb_decrypt:                           // a2 - uint32_t  * rk

    AES_LOAD_STATE $S0, $S1, $CT, $T0, $T1       // Load ciphertext

    ld      $T0, 5*32+0($RK)
    ld      $T1, 5*32+8($RK)

    xor     $S0, $S0, $T0
    xor     $S1, $S1, $T1

    DOUBLE_ROUND_DEC $RK, $K0, $K1, $T0, $T1, $S0, $S1, $N0, $N1, 4*32
    DOUBLE_ROUND_DEC $RK, $K0, $K1, $T0, $T1, $S0, $S1, $N0, $N1, 3*32
    DOUBLE_ROUND_DEC $RK, $K0, $K1, $T0, $T1, $S0, $S1, $N0, $N1, 2*32
    DOUBLE_ROUND_DEC $RK, $K0, $K1, $T0, $T1, $S0, $S1, $N0, $N1, 1*32
    LAST_2ROUNDS_DEC $RK, $K0, $K1, $T0, $T1, $S0, $S1, $N0, $N1, 0*32

    AES_DUMP_STATE $S0, $S1, $PT, $T0, $T1, 0    // Save plaintext

    ret
.endfunc


//
// AES 192 Decrypt
//

.func   aes_192_ecb_decrypt                    // a1 - uint8_t     pt [16],
.global aes_192_ecb_decrypt                    // a0 - uint8_t     ct [16],
aes_192_ecb_decrypt:                           // a2 - uint32_t  * rk

    AES_LOAD_STATE $S0, $S1, $CT, $T0, $T1       // Load ciphertext

    ld      $T0, 6*32+0($RK)
    ld      $T1, 6*32+8($RK)

    xor     $S0, $S0, $T0
    xor     $S1, $S1, $T1

    DOUBLE_ROUND_DEC $RK, $K0, $K1, $T0, $T1, $S0, $S1, $N0, $N1, 5*32
    DOUBLE_ROUND_DEC $RK, $K0, $K1, $T0, $T1, $S0, $S1, $N0, $N1, 4*32
    DOUBLE_ROUND_DEC $RK, $K0, $K1, $T0, $T1, $S0, $S1, $N0, $N1, 3*32
    DOUBLE_ROUND_DEC $RK, $K0, $K1, $T0, $T1, $S0, $S1, $N0, $N1, 2*32
    DOUBLE_ROUND_DEC $RK, $K0, $K1, $T0, $T1, $S0, $S1, $N0, $N1, 1*32
    LAST_2ROUNDS_DEC $RK, $K0, $K1, $T0, $T1, $S0, $S1, $N0, $N1, 0*32

    AES_DUMP_STATE $S0, $S1, $PT, $T0, $T1, 0    // Save plaintext

    ret
.endfunc

//
// AES 256 Decrypt
//

.func   aes_256_ecb_decrypt                    // a1 - uint8_t     pt [16],
.global aes_256_ecb_decrypt                    // a0 - uint8_t     ct [16],
aes_256_ecb_decrypt:                           // a2 - uint32_t  * rk

    AES_LOAD_STATE $S0, $S1, $CT, $T0, $T1       // Load ciphertext

    ld      $T0, 7*32+0($RK)
    ld      $T1, 7*32+8($RK)

    xor     $S0, $S0, $T0
    xor     $S1, $S1, $T1

    DOUBLE_ROUND_DEC $RK, $K0, $K1, $T0, $T1, $S0, $S1, $N0, $N1, 6*32
    DOUBLE_ROUND_DEC $RK, $K0, $K1, $T0, $T1, $S0, $S1, $N0, $N1, 5*32
    DOUBLE_ROUND_DEC $RK, $K0, $K1, $T0, $T1, $S0, $S1, $N0, $N1, 4*32
    DOUBLE_ROUND_DEC $RK, $K0, $K1, $T0, $T1, $S0, $S1, $N0, $N1, 3*32
    DOUBLE_ROUND_DEC $RK, $K0, $K1, $T0, $T1, $S0, $S1, $N0, $N1, 2*32
    DOUBLE_ROUND_DEC $RK, $K0, $K1, $T0, $T1, $S0, $S1, $N0, $N1, 1*32
    LAST_2ROUNDS_DEC $RK, $K0, $K1, $T0, $T1, $S0, $S1, $N0, $N1, 0*32

    AES_DUMP_STATE $S0, $S1, $PT, $T0, $T1, 0    // Save plaintext

    ret
.endfunc
___


print $code;
close STDOUT or die "error closing STDOUT: $!";    # enforce flush
