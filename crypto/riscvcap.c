/*
 * Copyright 2005-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#include <signal.h>
#include "internal/cryptlib.h"
#include "crypto/ctype.h"

#include "riscv_arch.h"

#if defined(__GNUC__) && defined(__linux)
__attribute__ ((visibility("hidden")))
#endif
unsigned int OPENSSL_riscvcap_P = 0;

int CRYPTO_memcmp(const void * in_a, const void * in_b, size_t len)
{
    size_t i;
    const volatile unsigned char *a = in_a;
    const volatile unsigned char *b = in_b;
    unsigned char x = 0;

    for (i = 0; i < len; i++)
        x |= a[i] ^ b[i];

    return x;
}

/*
 * For systems that don't provide an instruction counter register or equivalent.
 */
uint32_t OPENSSL_rdtsc(void)
{
    return 0;
}

size_t OPENSSL_instrument_bus(unsigned int *out, size_t cnt)
{
    return 0;
}

size_t OPENSSL_instrument_bus2(unsigned int *out, size_t cnt, size_t max)
{
    return 0;
}

static sigjmp_buf ill_jmp;
static void ill_handler(int sig)
{
    siglongjmp(ill_jmp, sig);
}

void OPENSSL_cpuid_setup(void)
{
    char *e;
    struct sigaction ill_act, oact_ill;
    sigset_t oset;
    static int trigger = 0;
    int rd = 0;
    int rs1 = 0;

    if (trigger)
        return;
    trigger = 1;

    if ((e = getenv("OPENSSL_riscvcap"))) {
        OPENSSL_riscvcap_P = strtoul(e, NULL, 0);
        return;
    }
    memset(&ill_act, 0, sizeof(ill_act));
    ill_act.sa_handler = ill_handler;
    sigfillset(&ill_act.sa_mask);
    sigdelset(&ill_act.sa_mask, SIGILL);
    sigprocmask(SIG_SETMASK, &ill_act.sa_mask, &oset);
    sigaction(SIGILL, &ill_act, &oact_ill);
    if (sigsetjmp(ill_jmp, 1) == 0) {
        __probe_k(rd, rs1);
        OPENSSL_riscvcap_P = MISA_K;
    }
    sigaction(SIGILL, &oact_ill, NULL);
    sigprocmask(SIG_SETMASK, &oset, NULL);

}
