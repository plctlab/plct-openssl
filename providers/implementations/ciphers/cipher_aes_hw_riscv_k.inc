/*
 * Copyright 2001-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*-
 * RISCV K support for AES modes ecb, cbc, ofb, cfb, ctr.
 * This file is included by cipher_aes_hw.c
 */

#define cipher_hw_riscv_k_ofb128_initkey    cipher_hw_aes_initkey
#define cipher_hw_riscv_k_cfb128_initkey    cipher_hw_aes_initkey
#define cipher_hw_riscv_k_cfb8_initkey      cipher_hw_aes_initkey
#define cipher_hw_riscv_k_cfb1_initkey      cipher_hw_aes_initkey
#define cipher_hw_riscv_k_ctr_initkey       cipher_hw_aes_initkey
#define cipher_hw_riscv_k_cbc_initkey       cipher_hw_riscv_k_initkey
#define cipher_hw_riscv_k_ecb_initkey       cipher_hw_riscv_k_initkey

#define cipher_hw_riscv_k_ofb128 ossl_cipher_hw_generic_ofb128
#define cipher_hw_riscv_k_cfb128 ossl_cipher_hw_generic_cfb128
#define cipher_hw_riscv_k_cfb8   ossl_cipher_hw_generic_cfb8
#define cipher_hw_riscv_k_cfb1   ossl_cipher_hw_generic_cfb1
#define cipher_hw_riscv_k_ctr    ossl_cipher_hw_generic_ctr
#define cipher_hw_riscv_k_cbc    ossl_cipher_hw_generic_cbc
#define cipher_hw_riscv_k_ecb    ossl_cipher_hw_generic_ecb

static int cipher_hw_riscv_k_initkey(PROV_CIPHER_CTX *dat,
                                   const unsigned char *key, size_t keylen)
{
    PROV_AES_CTX *adat = (PROV_AES_CTX *)dat;
    AES_KEY *ks = &adat->ks.ks;

    dat->ks = ks;

    if (!dat->enc) {
        switch (keylen) {
        case 16:
            aes_128_set_decrypt_key(ks->rd_key, key);
            ks->rounds = 10;
            dat->block = (block128_f)aes_128_ecb_decrypt;
            break;
        case 24:
            aes_192_set_decrypt_key(ks->rd_key, key);
            ks->rounds = 12;
            dat->block = (block128_f)aes_192_ecb_decrypt;
            break;
        case 32:
            aes_256_set_decrypt_key(ks->rd_key, key);
            ks->rounds = 14;
            dat->block = (block128_f)aes_256_ecb_decrypt;
            break;
        default:
            return 0;
        }
        dat->stream.cbc = NULL;
    } else {
        switch (keylen) {
        case 16:
            aes_128_set_encrypt_key(ks->rd_key, key);
            ks->rounds = 10;
            dat->block = (block128_f)aes_128_ecb_encrypt;
            break;
        case 24:
            aes_192_set_encrypt_key(ks->rd_key, key);
            ks->rounds = 12;
            dat->block = (block128_f)aes_192_ecb_encrypt;
            break;
        case 32:
            aes_256_set_encrypt_key(ks->rd_key, key);
            ks->rounds = 14;
            dat->block = (block128_f)aes_256_ecb_encrypt;
            break;
        default:
            return 0;
        }
        dat->stream.cbc = NULL;
    }

    return 1;
}

#define PROV_CIPHER_HW_declare(mode)                                           \
static const PROV_CIPHER_HW riscv_k_##mode = {                                   \
    cipher_hw_riscv_k_##mode##_initkey,                                                   \
    cipher_hw_riscv_k_##mode,                                                    \
    cipher_hw_aes_copyctx                                                      \
};
#define PROV_CIPHER_HW_select(mode)                                            \
if (RISCV_K_CAPABLE)                                                             \
    return &riscv_k_##mode;
