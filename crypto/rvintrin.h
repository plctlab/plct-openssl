/*
 *  RISC-V "B" extension proposal intrinsics and emulation
 *
 *  Copyright (C) 2019  Claire Wolf <claire@symbioticeda.com>
 *
 *  Permission to use, copy, modify, and/or distribute this software for any
 *  purpose with or without fee is hereby granted, provided that the above
 *  copyright notice and this permission notice appear in all copies.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 *  WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 *  ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 *  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 *  ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 *  OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *  ----------------------------------------------------------------------
 *
 *  Define RVINTRIN_EMULATE to enable emulation mode.
 *
 *  This header defines C inline functions with "mockup intrinsics" for
 *  RISC-V "B" extension proposal instructions.
 *
 *  _rv_*(...)
 *    RV32/64 intrinsics that operate on the "long" data type
 *
 *  _rv32_*(...)
 *    RV32/64 intrinsics that operate on the "int32_t" data type
 *
 *  _rv64_*(...)
 *    RV64-only intrinsics that operate on the "int64_t" data type
 *
 */

#ifndef RVINTRIN_H
#define RVINTRIN_H

#include <limits.h>
#include <stdint.h>

#if !defined(__riscv_xlen) && !defined(RVINTRIN_EMULATE)
#  warning "Target is not RISC-V. Enabling <rvintrin.h> emulation mode."
#  define RVINTRIN_EMULATE 1
#endif

#ifndef RVINTRIN_EMULATE

#if __riscv_xlen == 32
#  define RVINTRIN_RV32
#endif

#if __riscv_xlen == 64
#  define RVINTRIN_RV64
#endif


#ifdef RVINTRIN_RV32
static inline int32_t _rv32_pack (int32_t rs1, int32_t rs2) { int32_t rd; __asm__ ("pack  %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
static inline int32_t _rv32_packh(int32_t rs1, int32_t rs2) { int32_t rd; __asm__ ("packh %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
#endif

#ifdef RVINTRIN_RV64
static inline int32_t _rv32_pack (int32_t rs1, int32_t rs2) { int32_t rd; __asm__ ("packw  %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
static inline int32_t _rv32_packh(int32_t rs1, int32_t rs2) { int32_t rd; __asm__ ("packh  %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }

static inline int64_t _rv64_pack (int64_t rs1, int64_t rs2) { int64_t rd; __asm__ ("pack  %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
static inline int64_t _rv64_packh(int64_t rs1, int64_t rs2) { int64_t rd; __asm__ ("packh %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
#endif


#ifdef RVINTRIN_RV32
static inline int32_t _rv32_rol    (int32_t rs1, int32_t rs2) { int32_t rd; if (__builtin_constant_p(rs2)) __asm__ ("rori    %0, %1, %2" : "=r"(rd) : "r"(rs1), "i"(31 & -rs2)); else __asm__ ("rol     %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
static inline int32_t _rv32_ror    (int32_t rs1, int32_t rs2) { int32_t rd; if (__builtin_constant_p(rs2)) __asm__ ("rori    %0, %1, %2" : "=r"(rd) : "r"(rs1), "i"(31 &  rs2)); else __asm__ ("ror     %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
static inline int32_t _rv32_grev   (int32_t rs1, int32_t rs2) { int32_t rd; if (__builtin_constant_p(rs2)) __asm__ ("grevi   %0, %1, %2" : "=r"(rd) : "r"(rs1), "i"(31 &  rs2)); else __asm__ ("grev    %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
static inline int32_t _rv32_shfl   (int32_t rs1, int32_t rs2) { int32_t rd; if (__builtin_constant_p(rs2)) __asm__ ("shfli   %0, %1, %2" : "=r"(rd) : "r"(rs1), "i"(15 &  rs2)); else __asm__ ("shfl    %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
static inline int32_t _rv32_unshfl (int32_t rs1, int32_t rs2) { int32_t rd; if (__builtin_constant_p(rs2)) __asm__ ("unshfli %0, %1, %2" : "=r"(rd) : "r"(rs1), "i"(15 &  rs2)); else __asm__ ("unshfl  %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
#endif

#ifdef RVINTRIN_RV64
static inline int32_t _rv32_rol    (int32_t rs1, int32_t rs2) { int32_t rd; if (__builtin_constant_p(rs2)) __asm__ ("roriw   %0, %1, %2" : "=r"(rd) : "r"(rs1), "i"(31 & -rs2)); else __asm__ ("rolw    %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
static inline int32_t _rv32_ror    (int32_t rs1, int32_t rs2) { int32_t rd; if (__builtin_constant_p(rs2)) __asm__ ("roriw   %0, %1, %2" : "=r"(rd) : "r"(rs1), "i"(31 &  rs2)); else __asm__ ("rorw    %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
static inline int32_t _rv32_grev   (int32_t rs1, int32_t rs2) { int32_t rd; if (__builtin_constant_p(rs2)) __asm__ ("greviw  %0, %1, %2" : "=r"(rd) : "r"(rs1), "i"(31 &  rs2)); else __asm__ ("grevw   %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
static inline int32_t _rv32_shfl   (int32_t rs1, int32_t rs2) { int32_t rd; if (__builtin_constant_p(rs2)) __asm__ ("shfli   %0, %1, %2" : "=r"(rd) : "r"(rs1), "i"(15 &  rs2)); else __asm__ ("shflw   %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
static inline int32_t _rv32_unshfl (int32_t rs1, int32_t rs2) { int32_t rd; if (__builtin_constant_p(rs2)) __asm__ ("unshfli %0, %1, %2" : "=r"(rd) : "r"(rs1), "i"(15 &  rs2)); else __asm__ ("unshflw %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }

static inline int64_t _rv64_rol    (int64_t rs1, int64_t rs2) { int64_t rd; if (__builtin_constant_p(rs2)) __asm__ ("rori    %0, %1, %2" : "=r"(rd) : "r"(rs1), "i"(63 & -rs2)); else __asm__ ("rol     %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
static inline int64_t _rv64_ror    (int64_t rs1, int64_t rs2) { int64_t rd; if (__builtin_constant_p(rs2)) __asm__ ("rori    %0, %1, %2" : "=r"(rd) : "r"(rs1), "i"(63 &  rs2)); else __asm__ ("ror     %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
static inline int64_t _rv64_grev   (int64_t rs1, int64_t rs2) { int64_t rd; if (__builtin_constant_p(rs2)) __asm__ ("grevi   %0, %1, %2" : "=r"(rd) : "r"(rs1), "i"(63 &  rs2)); else __asm__ ("grev    %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
static inline int64_t _rv64_shfl   (int64_t rs1, int64_t rs2) { int64_t rd; if (__builtin_constant_p(rs2)) __asm__ ("shfli   %0, %1, %2" : "=r"(rd) : "r"(rs1), "i"(31 &  rs2)); else __asm__ ("shfl    %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
static inline int64_t _rv64_unshfl (int64_t rs1, int64_t rs2) { int64_t rd; if (__builtin_constant_p(rs2)) __asm__ ("unshfli %0, %1, %2" : "=r"(rd) : "r"(rs1), "i"(31 &  rs2)); else __asm__ ("unshfl  %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
#endif

#ifdef RVINTRIN_RV32
static inline int32_t _rv32_clmul (int32_t rs1, int32_t rs2) { int32_t rd; __asm__ ("clmul   %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
static inline int32_t _rv32_clmulh(int32_t rs1, int32_t rs2) { int32_t rd; __asm__ ("clmulh  %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
#endif

#ifdef RVINTRIN_RV64
static inline int32_t _rv32_clmul (int32_t rs1, int32_t rs2) { int32_t rd; __asm__ ("clmulw  %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
static inline int32_t _rv32_clmulh(int32_t rs1, int32_t rs2) { int32_t rd; __asm__ ("clmulhw %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }

static inline int64_t _rv64_clmul (int64_t rs1, int64_t rs2) { int64_t rd; __asm__ ("clmul   %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
static inline int64_t _rv64_clmulh(int64_t rs1, int64_t rs2) { int64_t rd; __asm__ ("clmulh  %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
#endif

#ifdef RVINTRIN_RV32
static inline int32_t _rv32_xperm_n(int32_t rs1, int32_t rs2) { int32_t rd; __asm__ ("xperm.n %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
static inline int32_t _rv32_xperm_b(int32_t rs1, int32_t rs2) { int32_t rd; __asm__ ("xperm.b %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
#endif

#ifdef RVINTRIN_RV64
static inline int32_t _rv32_xperm_n(int32_t rs1, int32_t rs2) { int32_t rd; __asm__ ("xpermw.n %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
static inline int32_t _rv32_xperm_b(int32_t rs1, int32_t rs2) { int32_t rd; __asm__ ("xpermw.b %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }

static inline int64_t _rv64_xperm_n(int64_t rs1, int64_t rs2) { int64_t rd; __asm__ ("xperm.n %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
static inline int64_t _rv64_xperm_b(int64_t rs1, int64_t rs2) { int64_t rd; __asm__ ("xperm.b %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
#endif

static inline long _rv_andn(long rs1, long rs2) { long rd; __asm__ ("andn %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
static inline long _rv_orn (long rs1, long rs2) { long rd; __asm__ ("orn  %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
static inline long _rv_xnor(long rs1, long rs2) { long rd; __asm__ ("xnor %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }

#else // RVINTRIN_EMULATE

#if UINT_MAX != 0xffffffffU
#  error "<rvintrin.h> emulation mode only supports systems with sizeof(int) = 4."
#endif

#if (ULLONG_MAX == 0xffffffffLLU) || (ULLONG_MAX != 0xffffffffffffffffLLU)
#  error "<rvintrin.h> emulation mode only supports systems with sizeof(long long) = 8."
#endif

#if UINT_MAX == ULONG_MAX
#  define RVINTRIN_RV32
#else
#  define RVINTRIN_RV64
#endif

static inline int32_t _rv32_pack(int32_t rs1, int32_t rs2) { return (rs1 & 0x0000ffff)   | (rs2 << 16); }
static inline int64_t _rv64_pack(int64_t rs1, int64_t rs2) { return (rs1 & 0xffffffffLL) | (rs2 << 32); }

static inline int32_t _rv32_packh(int32_t rs1, int32_t rs2) { return (rs1 & 0xff) | ((rs2 & 0xff) << 8); }
static inline int64_t _rv64_packh(int64_t rs1, int64_t rs2) { return (rs1 & 0xff) | ((rs2 & 0xff) << 8); }
static inline int32_t _rv32_rol    (int32_t rs1, int32_t rs2) { return _rv32_sll(rs1, rs2) | _rv32_srl(rs1, -rs2); }
static inline int32_t _rv32_ror    (int32_t rs1, int32_t rs2) { return _rv32_srl(rs1, rs2) | _rv32_sll(rs1, -rs2); }

static inline int32_t _rv32_grev(int32_t rs1, int32_t rs2)
{
	uint32_t x = rs1;
	int shamt = rs2 & 31;
	if (shamt &  1) x = ((x & 0x55555555) <<  1) | ((x & 0xAAAAAAAA) >>  1);
	if (shamt &  2) x = ((x & 0x33333333) <<  2) | ((x & 0xCCCCCCCC) >>  2);
	if (shamt &  4) x = ((x & 0x0F0F0F0F) <<  4) | ((x & 0xF0F0F0F0) >>  4);
	if (shamt &  8) x = ((x & 0x00FF00FF) <<  8) | ((x & 0xFF00FF00) >>  8);
	if (shamt & 16) x = ((x & 0x0000FFFF) << 16) | ((x & 0xFFFF0000) >> 16);
	return x;
}

static inline uint32_t _rvintrin_shuffle32_stage(uint32_t src, uint32_t maskL, uint32_t maskR, int N)
{
	uint32_t x = src & ~(maskL | maskR);
	x |= ((src <<  N) & maskL) | ((src >>  N) & maskR);
	return x;
}

static inline int32_t _rv32_shfl(int32_t rs1, int32_t rs2)
{
	uint32_t x = rs1;
	int shamt = rs2 & 15;

	if (shamt & 8) x = _rvintrin_shuffle32_stage(x, 0x00ff0000, 0x0000ff00, 8);
	if (shamt & 4) x = _rvintrin_shuffle32_stage(x, 0x0f000f00, 0x00f000f0, 4);
	if (shamt & 2) x = _rvintrin_shuffle32_stage(x, 0x30303030, 0x0c0c0c0c, 2);
	if (shamt & 1) x = _rvintrin_shuffle32_stage(x, 0x44444444, 0x22222222, 1);

	return x;
}

static inline int32_t _rv32_unshfl(int32_t rs1, int32_t rs2)
{
	uint32_t x = rs1;
	int shamt = rs2 & 15;

	if (shamt & 1) x = _rvintrin_shuffle32_stage(x, 0x44444444, 0x22222222, 1);
	if (shamt & 2) x = _rvintrin_shuffle32_stage(x, 0x30303030, 0x0c0c0c0c, 2);
	if (shamt & 4) x = _rvintrin_shuffle32_stage(x, 0x0f000f00, 0x00f000f0, 4);
	if (shamt & 8) x = _rvintrin_shuffle32_stage(x, 0x00ff0000, 0x0000ff00, 8);

	return x;
}

static inline int64_t _rv64_rol    (int64_t rs1, int64_t rs2) { return _rv64_sll(rs1, rs2) | _rv64_srl(rs1, -rs2); }
static inline int64_t _rv64_ror    (int64_t rs1, int64_t rs2) { return _rv64_srl(rs1, rs2) | _rv64_sll(rs1, -rs2); }

static inline int64_t _rv64_grev(int64_t rs1, int64_t rs2)
{
	uint64_t x = rs1;
	int shamt = rs2 & 63;
	if (shamt &  1) x = ((x & 0x5555555555555555LL) <<  1) | ((x & 0xAAAAAAAAAAAAAAAALL) >>  1);
	if (shamt &  2) x = ((x & 0x3333333333333333LL) <<  2) | ((x & 0xCCCCCCCCCCCCCCCCLL) >>  2);
	if (shamt &  4) x = ((x & 0x0F0F0F0F0F0F0F0FLL) <<  4) | ((x & 0xF0F0F0F0F0F0F0F0LL) >>  4);
	if (shamt &  8) x = ((x & 0x00FF00FF00FF00FFLL) <<  8) | ((x & 0xFF00FF00FF00FF00LL) >>  8);
	if (shamt & 16) x = ((x & 0x0000FFFF0000FFFFLL) << 16) | ((x & 0xFFFF0000FFFF0000LL) >> 16);
	if (shamt & 32) x = ((x & 0x00000000FFFFFFFFLL) << 32) | ((x & 0xFFFFFFFF00000000LL) >> 32);
	return x;
}

static inline uint64_t _rvintrin_shuffle64_stage(uint64_t src, uint64_t maskL, uint64_t maskR, int N)
{
	uint64_t x = src & ~(maskL | maskR);
	x |= ((src <<  N) & maskL) | ((src >>  N) & maskR);
	return x;
}

static inline int64_t _rv64_shfl(int64_t rs1, int64_t rs2)
{
	uint64_t x = rs1;
	int shamt = rs2 & 31;
	if (shamt & 16) x = _rvintrin_shuffle64_stage(x, 0x0000ffff00000000LL, 0x00000000ffff0000LL, 16);
	if (shamt &  8) x = _rvintrin_shuffle64_stage(x, 0x00ff000000ff0000LL, 0x0000ff000000ff00LL,  8);
	if (shamt &  4) x = _rvintrin_shuffle64_stage(x, 0x0f000f000f000f00LL, 0x00f000f000f000f0LL,  4);
	if (shamt &  2) x = _rvintrin_shuffle64_stage(x, 0x3030303030303030LL, 0x0c0c0c0c0c0c0c0cLL,  2);
	if (shamt &  1) x = _rvintrin_shuffle64_stage(x, 0x4444444444444444LL, 0x2222222222222222LL,  1);
	return x;
}

static inline int64_t _rv64_unshfl(int64_t rs1, int64_t rs2)
{
	uint64_t x = rs1;
	int shamt = rs2 & 31;
	if (shamt &  1) x = _rvintrin_shuffle64_stage(x, 0x4444444444444444LL, 0x2222222222222222LL,  1);
	if (shamt &  2) x = _rvintrin_shuffle64_stage(x, 0x3030303030303030LL, 0x0c0c0c0c0c0c0c0cLL,  2);
	if (shamt &  4) x = _rvintrin_shuffle64_stage(x, 0x0f000f000f000f00LL, 0x00f000f000f000f0LL,  4);
	if (shamt &  8) x = _rvintrin_shuffle64_stage(x, 0x00ff000000ff0000LL, 0x0000ff000000ff00LL,  8);
	if (shamt & 16) x = _rvintrin_shuffle64_stage(x, 0x0000ffff00000000LL, 0x00000000ffff0000LL, 16);
	return x;
}

static inline int32_t _rv32_clmul(int32_t rs1, int32_t rs2)
{
	uint32_t a = rs1, b = rs2, x = 0;
	for (int i = 0; i < 32; i++)
		if ((b >> i) & 1)
			x ^= a << i;
	return x;
}

static inline int32_t _rv32_clmulh(int32_t rs1, int32_t rs2)
{
	uint32_t a = rs1, b = rs2, x = 0;
	for (int i = 1; i < 32; i++)
		if ((b >> i) & 1)
			x ^= a >> (32-i);
	return x;
}

static inline int64_t _rv64_clmul(int64_t rs1, int64_t rs2)
{
	uint64_t a = rs1, b = rs2, x = 0;
	for (int i = 0; i < 64; i++)
		if ((b >> i) & 1)
			x ^= a << i;
	return x;
}

static inline int64_t _rv64_clmulh(int64_t rs1, int64_t rs2)
{
	uint64_t a = rs1, b = rs2, x = 0;
	for (int i = 1; i < 64; i++)
		if ((b >> i) & 1)
			x ^= a >> (64-i);
	return x;
}

static inline uint32_t _rvintrin_xperm32(uint32_t rs1, uint32_t rs2, int sz_log2)
{
	uint32_t r = 0;
	uint32_t sz = 1LL << sz_log2;
	uint32_t mask = (1LL << sz) - 1;
	for (int i = 0; i < 32; i += sz) {
		uint32_t pos = ((rs2 >> i) & mask) << sz_log2;
		if (pos < 32)
			r |= ((rs1 >> pos) & mask) << i;
	}
	return r;
}

static inline int32_t _rv32_xperm_n (int32_t rs1, int32_t rs2) { return _rvintrin_xperm32(rs1, rs2, 2); }
static inline int32_t _rv32_xperm_b (int32_t rs1, int32_t rs2) { return _rvintrin_xperm32(rs1, rs2, 3); }
static inline uint64_t _rvintrin_xperm64(uint64_t rs1, uint64_t rs2, int sz_log2)
{
	uint64_t r = 0;
	uint64_t sz = 1LL << sz_log2;
	uint64_t mask = (1LL << sz) - 1;
	for (int i = 0; i < 64; i += sz) {
		uint64_t pos = ((rs2 >> i) & mask) << sz_log2;
		if (pos < 64)
			r |= ((rs1 >> pos) & mask) << i;
	}
	return r;
}

static inline int64_t _rv64_xperm_n (int64_t rs1, int64_t rs2) { return _rvintrin_xperm64(rs1, rs2, 2); }
static inline int64_t _rv64_xperm_b (int64_t rs1, int64_t rs2) { return _rvintrin_xperm64(rs1, rs2, 3); }

static inline long _rv_andn(long rs1, long rs2) { return rs1 & ~rs2; }
static inline long _rv_orn (long rs1, long rs2) { return rs1 | ~rs2; }
static inline long _rv_xnor(long rs1, long rs2) { return rs1 ^ ~rs2; }

#endif // RVINTRIN_EMULATE

#ifdef RVINTRIN_RV32
static inline long _rv_pack     (long rs1, long rs2) { return _rv32_pack     (rs1, rs2); }
static inline long _rv_packh    (long rs1, long rs2) { return _rv32_packh    (rs1, rs2); }
static inline long _rv_rol      (long rs1, long rs2) { return _rv32_rol      (rs1, rs2); }
static inline long _rv_ror      (long rs1, long rs2) { return _rv32_ror      (rs1, rs2); }
static inline long _rv_grev     (long rs1, long rs2) { return _rv32_grev     (rs1, rs2); }
static inline long _rv_shfl     (long rs1, long rs2) { return _rv32_shfl     (rs1, rs2); }
static inline long _rv_unshfl   (long rs1, long rs2) { return _rv32_unshfl   (rs1, rs2); }
static inline long _rv_clmul    (long rs1, long rs2) { return _rv32_clmul    (rs1, rs2); }
static inline long _rv_clmulh   (long rs1, long rs2) { return _rv32_clmulh   (rs1, rs2); }
static inline long _rv_xperm_n  (long rs1, long rs2) { return _rv32_xperm_n  (rs1, rs2); }
static inline long _rv_xperm_b  (long rs1, long rs2) { return _rv32_xperm_b  (rs1, rs2); }
#endif

#ifdef RVINTRIN_RV64
static inline long _rv_pack     (long rs1, long rs2) { return _rv64_pack     (rs1, rs2); }
static inline long _rv_packh    (long rs1, long rs2) { return _rv64_packh    (rs1, rs2); }
static inline long _rv_rol      (long rs1, long rs2) { return _rv64_rol      (rs1, rs2); }
static inline long _rv_ror      (long rs1, long rs2) { return _rv64_ror      (rs1, rs2); }
static inline long _rv_grev     (long rs1, long rs2) { return _rv64_grev     (rs1, rs2); }
static inline long _rv_shfl     (long rs1, long rs2) { return _rv64_shfl     (rs1, rs2); }
static inline long _rv_unshfl   (long rs1, long rs2) { return _rv64_unshfl   (rs1, rs2); }
static inline long _rv_clmul    (long rs1, long rs2) { return _rv64_clmul    (rs1, rs2); }
static inline long _rv_clmulh   (long rs1, long rs2) { return _rv64_clmulh   (rs1, rs2); }
static inline long _rv_xperm_n  (long rs1, long rs2) { return _rv64_xperm_n  (rs1, rs2); }
static inline long _rv_xperm_b  (long rs1, long rs2) { return _rv64_xperm_b  (rs1, rs2); }
#endif

#ifdef RVINTRIN_RV32

#define RVINTRIN_GREV_PSEUDO_OP32(_arg, _name) \
	static inline long    _rv_   ## _name(long    rs1) { return _rv_grev  (rs1, _arg); } \
	static inline int32_t _rv32_ ## _name(int32_t rs1) { return _rv32_grev(rs1, _arg); }

#define RVINTRIN_GREV_PSEUDO_OP64(_arg, _name)

#else

#define RVINTRIN_GREV_PSEUDO_OP32(_arg, _name) \
	static inline int32_t _rv32_ ## _name(int32_t rs1) { return _rv32_grev(rs1, _arg); }

#define RVINTRIN_GREV_PSEUDO_OP64(_arg, _name) \
	static inline long    _rv_   ## _name(long    rs1) { return _rv_grev  (rs1, _arg); } \
	static inline int64_t _rv64_ ## _name(int64_t rs1) { return _rv64_grev(rs1, _arg); }
#endif

RVINTRIN_GREV_PSEUDO_OP32( 1, rev_p)
RVINTRIN_GREV_PSEUDO_OP32( 2, rev2_n)
RVINTRIN_GREV_PSEUDO_OP32( 3, rev_n)
RVINTRIN_GREV_PSEUDO_OP32( 4, rev4_b)
RVINTRIN_GREV_PSEUDO_OP32( 6, rev2_b)
RVINTRIN_GREV_PSEUDO_OP32( 7, rev_b)
RVINTRIN_GREV_PSEUDO_OP32( 8, rev8_h)
RVINTRIN_GREV_PSEUDO_OP32(12, rev4_h)
RVINTRIN_GREV_PSEUDO_OP32(14, rev2_h)
RVINTRIN_GREV_PSEUDO_OP32(15, rev_h)
RVINTRIN_GREV_PSEUDO_OP32(16, rev16)
RVINTRIN_GREV_PSEUDO_OP32(24, rev8)
RVINTRIN_GREV_PSEUDO_OP32(28, rev4)
RVINTRIN_GREV_PSEUDO_OP32(30, rev2)
RVINTRIN_GREV_PSEUDO_OP32(31, rev)

RVINTRIN_GREV_PSEUDO_OP64( 1, rev_p)
RVINTRIN_GREV_PSEUDO_OP64( 2, rev2_n)
RVINTRIN_GREV_PSEUDO_OP64( 3, rev_n)
RVINTRIN_GREV_PSEUDO_OP64( 4, rev4_b)
RVINTRIN_GREV_PSEUDO_OP64( 6, rev2_b)
RVINTRIN_GREV_PSEUDO_OP64( 7, rev_b)
RVINTRIN_GREV_PSEUDO_OP64( 8, rev8_h)
RVINTRIN_GREV_PSEUDO_OP64(12, rev4_h)
RVINTRIN_GREV_PSEUDO_OP64(14, rev2_h)
RVINTRIN_GREV_PSEUDO_OP64(15, rev_h)
RVINTRIN_GREV_PSEUDO_OP64(16, rev16_w)
RVINTRIN_GREV_PSEUDO_OP64(24, rev8_w)
RVINTRIN_GREV_PSEUDO_OP64(28, rev4_w)
RVINTRIN_GREV_PSEUDO_OP64(30, rev2_w)
RVINTRIN_GREV_PSEUDO_OP64(31, rev_w)
RVINTRIN_GREV_PSEUDO_OP64(32, rev32)
RVINTRIN_GREV_PSEUDO_OP64(48, rev16)
RVINTRIN_GREV_PSEUDO_OP64(56, rev8)
RVINTRIN_GREV_PSEUDO_OP64(60, rev4)
RVINTRIN_GREV_PSEUDO_OP64(62, rev2)
RVINTRIN_GREV_PSEUDO_OP64(63, rev)

#ifdef RVINTRIN_RV32

#define RVINTRIN_SHFL_PSEUDO_OP32(_arg, _name) \
	static inline long    _rv_     ## _name(long    rs1) { return _rv_shfl    (rs1, _arg); } \
	static inline long    _rv_un   ## _name(long    rs1) { return _rv_unshfl  (rs1, _arg); } \
	static inline int32_t _rv32_   ## _name(int32_t rs1) { return _rv32_shfl  (rs1, _arg); } \
	static inline int32_t _rv32_un ## _name(int32_t rs1) { return _rv32_unshfl(rs1, _arg); }

#define RVINTRIN_SHFL_PSEUDO_OP64(_arg, _name)

#else

#define RVINTRIN_SHFL_PSEUDO_OP32(_arg, _name) \
	static inline int64_t _rv32_   ## _name(int64_t rs1) { return _rv32_shfl  (rs1, _arg); } \
	static inline int64_t _rv32_un ## _name(int64_t rs1) { return _rv32_unshfl(rs1, _arg); }

#define RVINTRIN_SHFL_PSEUDO_OP64(_arg, _name) \
	static inline long    _rv_     ## _name(long    rs1) { return _rv_shfl    (rs1, _arg); } \
	static inline long    _rv_un   ## _name(long    rs1) { return _rv_unshfl  (rs1, _arg); } \
	static inline int64_t _rv64_   ## _name(int64_t rs1) { return _rv64_shfl  (rs1, _arg); } \
	static inline int64_t _rv64_un ## _name(int64_t rs1) { return _rv64_unshfl(rs1, _arg); }

#endif

RVINTRIN_SHFL_PSEUDO_OP32( 1, zip_n)
RVINTRIN_SHFL_PSEUDO_OP32( 2, zip2_b)
RVINTRIN_SHFL_PSEUDO_OP32( 3, zip_b)
RVINTRIN_SHFL_PSEUDO_OP32( 4, zip4_h)
RVINTRIN_SHFL_PSEUDO_OP32( 6, zip2_h)
RVINTRIN_SHFL_PSEUDO_OP32( 7, zip_h)
RVINTRIN_SHFL_PSEUDO_OP32( 8, zip8)
RVINTRIN_SHFL_PSEUDO_OP32(12, zip4)
RVINTRIN_SHFL_PSEUDO_OP32(14, zip2)
RVINTRIN_SHFL_PSEUDO_OP32(15, zip)

RVINTRIN_SHFL_PSEUDO_OP64( 1, zip_n)
RVINTRIN_SHFL_PSEUDO_OP64( 2, zip2_b)
RVINTRIN_SHFL_PSEUDO_OP64( 3, zip_b)
RVINTRIN_SHFL_PSEUDO_OP64( 4, zip4_h)
RVINTRIN_SHFL_PSEUDO_OP64( 6, zip2_h)
RVINTRIN_SHFL_PSEUDO_OP64( 7, zip_h)
RVINTRIN_SHFL_PSEUDO_OP64( 8, zip8_w)
RVINTRIN_SHFL_PSEUDO_OP64(12, zip4_w)
RVINTRIN_SHFL_PSEUDO_OP64(14, zip2_w)
RVINTRIN_SHFL_PSEUDO_OP64(15, zip_w)
RVINTRIN_SHFL_PSEUDO_OP64(16, zip16)
RVINTRIN_SHFL_PSEUDO_OP64(24, zip8)
RVINTRIN_SHFL_PSEUDO_OP64(28, zip4)
RVINTRIN_SHFL_PSEUDO_OP64(30, zip2)
RVINTRIN_SHFL_PSEUDO_OP64(31, zip)

#endif // RVINTRIN_H
