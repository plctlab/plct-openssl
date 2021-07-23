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
#include "crypto/sha.h"
#if defined(__riscv)
#include "riscv_arch.h"
extern unsigned int OPENSSL_riscvcap_P;
# define RISCV_SHA_CAPABLE         (OPENSSL_riscvcap_P & RISCV_K_ZKSH)
# define ARCH_SHA256_Sigma0(x)  _rv_sha256sum0((x))
# define ARCH_SHA256_Sigma1(x)  _rv_sha256sum1((x))
# define ARCH_SHA256_sigma0(x)  _rv_sha256sig0((x))
# define ARCH_SHA256_sigma1(x)  _rv_sha256sig1((x))
# define ARCH_SHA256_CAPABLE RISCV_SHA_CAPABLE
#if (__riscv_xlen == 32)
# define ARCH_SHA512_Sigma0(x) (((uint64_t)_rv32_sha512sum0r((uint32_t)(x >> 32),(uint32_t)x)) << 32 | ((uint64_t)_rv32_sha512sum0r((uint32_t)x,(uint32_t)(x >> 32))))
# define ARCH_SHA512_Sigma1(x) (((uint64_t)_rv32_sha512sum1r((uint32_t)(x >> 32),(uint32_t)x)) << 32 | ((uint64_t)_rv32_sha512sum1r((uint32_t)x,(uint32_t)(x >> 32))))
# define ARCH_SHA512_sigma0(x) (((uint64_t)_rv32_sha512sig0h((uint32_t)(x >> 32),(uint32_t)x)) << 32 | ((uint64_t)_rv32_sha512sig0l((uint32_t)x,(uint32_t)(x >> 32))))
# define ARCH_SHA512_sigma1(x) (((uint64_t)_rv32_sha512sig1h((uint32_t)(x >> 32),(uint32_t)x)) << 32 | ((uint64_t)_rv32_sha512sig1l((uint32_t)x,(uint32_t)(x >> 32))))
#elif (__riscv_xlen == 64)
# define ARCH_SHA512_Sigma0(x)     _rv64_sha512sum0((x))
# define ARCH_SHA512_Sigma1(x)     _rv64_sha512sum1((x))
# define ARCH_SHA512_sigma0(x)     _rv64_sha512sig0((x))
# define ARCH_SHA512_sigma1(x)     _rv64_sha512sig1((x))
#endif
# define ARCH_SHA512_CAPABLE RISCV_SHA_CAPABLE
#endif
#endif
