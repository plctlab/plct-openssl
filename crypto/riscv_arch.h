/*
 * Copyright 2012-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_CRYPTO_RISCV_ARCH_H
# define OSSL_CRYPTO_RISCV_ARCH_H
#include "rv_endian.h"
#include "rvkintrin.h"
#include "rvintrin.h"
#define RISCV_K_ZKND  (1 << 0)
#define RISCV_K_ZKNE  (1 << 1)
#define RISCV_K_ZKNH  (1 << 2)
#define RISCV_K_ZKSED (1 << 3)
#define RISCV_K_ZKSH  (1 << 4)

#if (__riscv_xlen == 32)
#define riscv_zknd_probe(rs1, rs2) _rv32_aes32dsi(rs1, rs2, 0)
#define riscv_zkne_probe(rs1, rs2) _rv32_aes32esi(rs1, rs2, 0)
#else  // __riscv_xlen == 64
#define riscv_zknd_probe(rs1, rs2) _rv64_aes64dsm(rs1, rs2)
#define riscv_zkne_probe(rs1, rs2) _rv64_aes64esm(rs1, rs2)
#endif
#define riscv_zknh_probe(rs1)  _rv_sha256sig0(rs1)
#define riscv_zksed_probe(rs1, rs2)  _rv_sm4ks(rs1, rs2, 0)
#define riscv_zksh_probe(rs1)  _rv_sm3p0(rs1)
#endif                          /* OSSL_CRYPTO_RISCV_ARCH_H */
