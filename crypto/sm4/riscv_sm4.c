/*
 * Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2017 Ribose Inc. All Rights Reserved.
 * Ported from Ribose contributions from Botan.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/e_os2.h>
#include "crypto/sm4_platform.h"

static inline uint32_t sm4_ks4(uint32_t rs1, uint32_t rs2) {
    rs1 = _rv_sm4ks(rs1, rs2, 0);
    rs1 = _rv_sm4ks(rs1, rs2, 1);
    rs1 = _rv_sm4ks(rs1, rs2, 2);
    rs1 = _rv_sm4ks(rs1, rs2, 3);
    return rs1;
}

int arch_SM4_set_key(const uint8_t *key, SM4_KEY *ks)
{
    /*
     * Family Key
     */
    const uint32_t FK[4] =
        { 0xC6BAB1A3, 0x5033AA56, 0x97917D67, 0xDC2270B2 };

    /*
     * Constant Key
     */
    const uint32_t CK [32] = {
        0x150E0700, 0x312A231C, 0x4D463F38, 0x69625B54,
        0x857E7770, 0xA19A938C, 0xBDB6AFA8, 0xD9D2CBC4,
        0xF5EEE7E0, 0x110A03FC, 0x2D261F18, 0x49423B34,
        0x655E5750, 0x817A736C, 0x9D968F88, 0xB9B2ABA4,
        0xD5CEC7C0, 0xF1EAE3DC, 0x0D06FFF8, 0x29221B14,
        0x453E3730, 0x615A534C, 0x7D766F68, 0x99928B84,
        0xB5AEA7A0, 0xD1CAC3BC, 0xEDE6DFD8, 0x0902FBF4,
        0x251E1710, 0x413A332C, 0x5D564F48, 0x79726B64
    };

    uint32_t* key_word = (uint32_t*) key;
    uint32_t K[4];
    int i;

    K[0] = key_word[0] ^ FK[0];
    K[1] = key_word[1] ^ FK[1];
    K[2] = key_word[2] ^ FK[2];
    K[3] = key_word[3] ^ FK[3];

    for (i = 0; i != SM4_KEY_SCHEDULE; ++i) {
        uint32_t X = K[(i + 1) % 4] ^ K[(i + 2) % 4] ^ K[(i + 3) % 4] ^ CK[i];
        K[i % 4]= sm4_ks4(K[i % 4], X);
        put32u_be((uint8_t *)&ks->rk[i], K[i % 4]);
    }
    return 1;
}

#define SM4_RNDS(k0, k1, k2, k3, F)          \
      do {                                   \
         B0 ^= F(B1 ^ B2 ^ B3 ^ ks->rk[k0]); \
         B1 ^= F(B0 ^ B2 ^ B3 ^ ks->rk[k1]); \
         B2 ^= F(B0 ^ B1 ^ B3 ^ ks->rk[k2]); \
         B3 ^= F(B0 ^ B1 ^ B2 ^ ks->rk[k3]); \
      } while(0)

static inline uint32_t sm4_ed4(uint32_t rs1, uint32_t rs2) {
    rs1 = _rv_sm4ed(rs1, rs2, 0);
    rs1 = _rv_sm4ed(rs1, rs2, 1);
    rs1 = _rv_sm4ed(rs1, rs2, 2);
    rs1 = _rv_sm4ed(rs1, rs2, 3);
    return rs1;
}

#define RISCV_SM4_RNDS(k0, k1, k2, k3)          \
      do {                                   \
         B0 = sm4_ed4(B0, B1 ^ B2 ^ B3 ^ get32u_be((uint8_t *)ks->rk + 4 * k0)); \
         B1 = sm4_ed4(B1, B0 ^ B2 ^ B3 ^ get32u_be((uint8_t *)ks->rk + 4 * k1)); \
         B2 = sm4_ed4(B2, B0 ^ B1 ^ B3 ^ get32u_be((uint8_t *)ks->rk + 4 * k2)); \
         B3 = sm4_ed4(B3, B0 ^ B1 ^ B2 ^ get32u_be((uint8_t *)ks->rk + 4 * k3)); \
      } while(0)


void arch_SM4_encrypt(const uint8_t *in, uint8_t *out, const SM4_KEY *ks)
{
    uint32_t B0 = get32u_le(in);
    uint32_t B1 = get32u_le(in + 4);
    uint32_t B2 = get32u_le(in + 8);
    uint32_t B3 = get32u_le(in + 12);

    RISCV_SM4_RNDS( 0,  1,  2,  3);
    RISCV_SM4_RNDS( 4,  5,  6,  7);
    RISCV_SM4_RNDS( 8,  9, 10, 11);
    RISCV_SM4_RNDS(12, 13, 14, 15);
    RISCV_SM4_RNDS(16, 17, 18, 19);
    RISCV_SM4_RNDS(20, 21, 22, 23);
    RISCV_SM4_RNDS(24, 25, 26, 27);
    RISCV_SM4_RNDS(28, 29, 30, 31);

    put32u_le(out, B3);
    put32u_le(out + 4, B2);
    put32u_le(out + 8, B1);
    put32u_le(out + 12, B0);
}

void arch_SM4_decrypt(const uint8_t *in, uint8_t *out, const SM4_KEY *ks)
{
    uint32_t B0 = get32u_le(in);
    uint32_t B1 = get32u_le(in + 4);
    uint32_t B2 = get32u_le(in + 8);
    uint32_t B3 = get32u_le(in + 12);

    RISCV_SM4_RNDS(31, 30, 29, 28);
    RISCV_SM4_RNDS(27, 26, 25, 24);
    RISCV_SM4_RNDS(23, 22, 21, 20);
    RISCV_SM4_RNDS(19, 18, 17, 16);
    RISCV_SM4_RNDS(15, 14, 13, 12);
    RISCV_SM4_RNDS(11, 10,  9,  8);
    RISCV_SM4_RNDS( 7,  6,  5,  4);
    RISCV_SM4_RNDS( 3,  2,  1,  0);

    put32u_le(out, B3);
    put32u_le(out + 4, B2);
    put32u_le(out + 8, B1);
    put32u_le(out + 12, B0);
}
