/*
 * Copyright 2017-2021 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2017 Ribose Inc. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_CRYPTO_SHA_PLATFORM_H
# define OSSL_CRYPTO_SHA_PLATFORM_H
#if defined(__riscv)
#include "riscv_arch.h"
extern unsigned int OPENSSL_riscvcap_P;
# define RISCV_SM3_CAPABLE         (OPENSSL_riscvcap_P & RISCV_K_ZKSH)
#define ARCH_P0(X) _rv_sm3p0(X)
#define ARCH_P1(X) _rv_sm3p1(X)

# define ARCH_SM3_CAPABLE RISCV_SM3_CAPABLE
#endif
#endif
