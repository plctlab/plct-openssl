/*
 * Copyright 2017-2021 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2017 Ribose Inc. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_CRYPTO_SM4_PLATFORM_H
# define OSSL_CRYPTO_SM4_PLATFORM_H
#include "crypto/sm4.h"
#if defined(OPENSSL_CPUID_OBJ)&& defined(__riscv)
#include "riscv_arch.h"
extern unsigned int OPENSSL_riscvcap_P;
#define RISCV_SM4_CAPABLE         (OPENSSL_riscvcap_P & RISCV_K_ZKSED)
int arch_SM4_set_key(const uint8_t *key, SM4_KEY *ks);
void arch_SM4_encrypt(const uint8_t *in, uint8_t *out, const SM4_KEY *ks);
void arch_SM4_decrypt(const uint8_t *in, uint8_t *out, const SM4_KEY *ks);
#else
#define arch_SM4_set_key SM4_set_key
#define arch_SM4_encrypt SM4_encrypt
#define arch_SM4_decrypt SM4_decrypt
#endif
#endif
