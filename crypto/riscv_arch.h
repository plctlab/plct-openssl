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

# define MISA_K (1<<0)

#define __probe_k(rd, rs1)  __asm__ __volatile__("sm3p0 %0, %1" : "=r"(rd) : "r"(rs1))


#endif                          /* OSSL_CRYPTO_SPARC_ARCH_H */
