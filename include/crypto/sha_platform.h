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
#if defined(OPENSSL_CPUID_OBJ)&& defined(__riscv)
#include "riscv_arch.h"
extern unsigned int OPENSSL_riscvcap_P;
# define RISCV_SHA_CAPABLE         (OPENSSL_riscvcap_P & RISCV_K_ZKSH)
inline long arch_sha256_Sigma0(long x) { if(RISCV_SHA_CAPABLE) return _rv_sha256sum0(x); else return _Sigma0(x); }
inline long arch_sha256_Sigma1(long x) { if(RISCV_SHA_CAPABLE) return _rv_sha256sum1((x)); else return _Sigma1(x); }
inline long arch_sha256_sigma0(long x) { if(RISCV_SHA_CAPABLE) return _rv_sha256sig0((x)); else return _sigma0(x); }
inline long arch_sha256_sigma1(long x) { if(RISCV_SHA_CAPABLE) return _rv_sha256sig1((x)); else return _sigma1(x); }
# define arch_sha256_CAPABLE RISCV_SHA_CAPABLE
#if (__riscv_xlen == 32)
inline uint64_t arch_sha512_Sigma0(uint64_t x) {
    if(RISCV_SHA_CAPABLE)
        return (((uint64_t)_rv32_sha512sum0r((uint32_t)(x >> 32),(uint32_t)x)) << 32 | ((uint64_t)_rv32_sha512sum0r((uint32_t)x,(uint32_t)(x >> 32))))
    else
        return _Sigma0(x);
}
inline uint64_t arch_sha512_Sigma1(uint64_t x) {
    if(RISCV_SHA_CAPABLE)
        return (((uint64_t)_rv32_sha512sum1r((uint32_t)(x >> 32),(uint32_t)x)) << 32 | ((uint64_t)_rv32_sha512sum1r((uint32_t)x,(uint32_t)(x >> 32))));
    else
        return _Sigma1(x);
}
inline uint64_t arch_sha512_sigma0(uint64_t x) {
    if(RISCV_SHA_CAPABLE)
        return (((uint64_t)_rv32_sha512sig0h((uint32_t)(x >> 32),(uint32_t)x)) << 32 | ((uint64_t)_rv32_sha512sig0l((uint32_t)x,(uint32_t)(x >> 32))));
    else
        return _sigma0(x);
}
inline uint64_t arch_sha512_sigma1(uint64_t x) {
    if(RISCV_SHA_CAPABLE)
        return (((uint64_t)_rv32_sha512sig1h((uint32_t)(x >> 32),(uint32_t)x)) << 32 | ((uint64_t)_rv32_sha512sig1l((uint32_t)x,(uint32_t)(x >> 32))));
    else
        return _sigma1(x);
}
#elif (__riscv_xlen == 64)
inline uint64_t arch_sha512_Sigma0(uint64_t x) { if(RISCV_SHA_CAPABLE) return _rv64_sha512sum0((x)); else return _Sigma0(x); }
inline uint64_t arch_sha512_Sigma1(uint64_t x) { if(RISCV_SHA_CAPABLE) return _rv64_sha512sum1((x)); else return _Sigma1(x); }
inline uint64_t arch_sha512_sigma0(uint64_t x) { if(RISCV_SHA_CAPABLE) return _rv64_sha512sig0((x)); else return _sigma0(x); }
inline uint64_t arch_sha512_sigma1(uint64_t x) { if(RISCV_SHA_CAPABLE) return _rv64_sha512sig1((x)); else return _sigma1(x); }
#endif
# define arch_sha512_CAPABLE RISCV_SHA_CAPABLE
#endif
#endif
