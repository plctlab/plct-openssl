#include <openssl/e_os2.h>
#include <string.h>
#include <assert.h>

#define SHA3_PLATFORM
#include "crypto/sha_platform.h"
#undef SHA3_PLATFORM
#if (__riscv_xlen == 64)
void riscv_KeccakF1600(uint64_t s[5][5])
{
	//	round constants
	const uint64_t rc[24] = {
		0x0000000000000001LLU, 0x0000000000008082LLU, 0x800000000000808ALLU,
		0x8000000080008000LLU, 0x000000000000808BLLU, 0x0000000080000001LLU,
		0x8000000080008081LLU, 0x8000000000008009LLU, 0x000000000000008ALLU,
		0x0000000000000088LLU, 0x0000000080008009LLU, 0x000000008000000ALLU,
		0x000000008000808BLLU, 0x800000000000008BLLU, 0x8000000000008089LLU,
		0x8000000000008003LLU, 0x8000000000008002LLU, 0x8000000000000080LLU,
		0x000000000000800ALLU, 0x800000008000000ALLU, 0x8000000080008081LLU,
		0x8000000000008080LLU, 0x0000000080000001LLU, 0x8000000080008008LL
	};

	int i;
	uint64_t t, u, v, w;
	uint64_t sa, sb, sc, sd, se, sf, sg, sh, si, sj, sk, sl, sm,
		sn, so, sp, sq, sr, ss, st, su, sv, sw, sx, sy;

	//	load state, little endian, aligned

	uint64_t *vs = (uint64_t *) s;

	sa = vs[0];
	sb = vs[1];
	sc = vs[2];
	sd = vs[3];
	se = vs[4];
	sf = vs[5];
	sg = vs[6];
	sh = vs[7];
	si = vs[8];
	sj = vs[9];
	sk = vs[10];
	sl = vs[11];
	sm = vs[12];
	sn = vs[13];
	so = vs[14];
	sp = vs[15];
	sq = vs[16];
	sr = vs[17];
	ss = vs[18];
	st = vs[19];
	su = vs[20];
	sv = vs[21];
	sw = vs[22];
	sx = vs[23];
	sy = vs[24];

	//	iteration

	for (i = 0; i < 24; i++) {

		//	Theta

		u = sa ^ sf ^ sk ^ sp ^ su;
		v = sb ^ sg ^ sl ^ sq ^ sv;
		w = se ^ sj ^ so ^ st ^ sy;
		t = w ^ _rv64_ror(v, 63);
		sa = sa ^ t;
		sf = sf ^ t;
		sk = sk ^ t;
		sp = sp ^ t;
		su = su ^ t;

		t = sd ^ si ^ sn ^ ss ^ sx;
		v = v ^ _rv64_ror(t, 63);
		t = t ^ _rv64_ror(u, 63);
		se = se ^ t;
		sj = sj ^ t;
		so = so ^ t;
		st = st ^ t;
		sy = sy ^ t;

		t = sc ^ sh ^ sm ^ sr ^ sw;
		u = u ^ _rv64_ror(t, 63);
		t = t ^ _rv64_ror(w, 63);
		sc = sc ^ v;
		sh = sh ^ v;
		sm = sm ^ v;
		sr = sr ^ v;
		sw = sw ^ v;

		sb = sb ^ u;
		sg = sg ^ u;
		sl = sl ^ u;
		sq = sq ^ u;
		sv = sv ^ u;

		sd = sd ^ t;
		si = si ^ t;
		sn = sn ^ t;
		ss = ss ^ t;
		sx = sx ^ t;

		//	Rho Pi

		t = _rv64_ror(sb, 63);
		sb = _rv64_ror(sg, 20);
		sg = _rv64_ror(sj, 44);
		sj = _rv64_ror(sw, 3);
		sw = _rv64_ror(so, 25);
		so = _rv64_ror(su, 46);
		su = _rv64_ror(sc, 2);
		sc = _rv64_ror(sm, 21);
		sm = _rv64_ror(sn, 39);
		sn = _rv64_ror(st, 56);
		st = _rv64_ror(sx, 8);
		sx = _rv64_ror(sp, 23);
		sp = _rv64_ror(se, 37);
		se = _rv64_ror(sy, 50);
		sy = _rv64_ror(sv, 62);
		sv = _rv64_ror(si, 9);
		si = _rv64_ror(sq, 19);
		sq = _rv64_ror(sf, 28);
		sf = _rv64_ror(sd, 36);
		sd = _rv64_ror(ss, 43);
		ss = _rv64_ror(sr, 49);
		sr = _rv64_ror(sl, 54);
		sl = _rv64_ror(sh, 58);
		sh = _rv64_ror(sk, 61);
		sk = t;

		//	Chi

		t = _rv_andn(se, sd);
		se = se ^ _rv_andn(sb, sa);
		sb = sb ^ _rv_andn(sd, sc);
		sd = sd ^ _rv_andn(sa, se);
		sa = sa ^ _rv_andn(sc, sb);
		sc = sc ^ t;

		t = _rv_andn(sj, si);
		sj = sj ^ _rv_andn(sg, sf);
		sg = sg ^ _rv_andn(si, sh);
		si = si ^ _rv_andn(sf, sj);
		sf = sf ^ _rv_andn(sh, sg);
		sh = sh ^ t;

		t = _rv_andn(so, sn);
		so = so ^ _rv_andn(sl, sk);
		sl = sl ^ _rv_andn(sn, sm);
		sn = sn ^ _rv_andn(sk, so);
		sk = sk ^ _rv_andn(sm, sl);
		sm = sm ^ t;

		t = _rv_andn(st, ss);
		st = st ^ _rv_andn(sq, sp);
		sq = sq ^ _rv_andn(ss, sr);
		ss = ss ^ _rv_andn(sp, st);
		sp = sp ^ _rv_andn(sr, sq);
		sr = sr ^ t;

		t = _rv_andn(sy, sx);
		sy = sy ^ _rv_andn(sv, su);
		sv = sv ^ _rv_andn(sx, sw);
		sx = sx ^ _rv_andn(su, sy);
		su = su ^ _rv_andn(sw, sv);
		sw = sw ^ t;

		//	Iota

		sa = sa ^ rc[i];
	}

	//	store state

	vs[0] = sa;
	vs[1] = sb;
	vs[2] = sc;
	vs[3] = sd;
	vs[4] = se;
	vs[5] = sf;
	vs[6] = sg;
	vs[7] = sh;
	vs[8] = si;
	vs[9] = sj;
	vs[10] = sk;
	vs[11] = sl;
	vs[12] = sm;
	vs[13] = sn;
	vs[14] = so;
	vs[15] = sp;
	vs[16] = sq;
	vs[17] = sr;
	vs[18] = ss;
	vs[19] = st;
	vs[20] = su;
	vs[21] = sv;
	vs[22] = sw;
	vs[23] = sx;
	vs[24] = sy;
}
#else
static void sha3_f1600_rvb32_split(uint32_t v[50])
{
	uint32_t t0, t1, *p;

	for (p = v; p != &v[50]; p += 2) {
		//	uses bitmanip UNSHFL with immediate 15, which is pseudo-op "unzip"
		t0 = _rv32_unzip(p[0]);
		t1 = _rv32_unzip(p[1]);
		p[0] = (t0 & 0x0000FFFF) | (t1 << 16);
		p[1] = (t1 & 0xFFFF0000) | (t0 >> 16);
	}
}

//	even/odd bit join the halves of the state words (for output)

static void sha3_f1600_rvb32_join(uint32_t v[50])
{
	uint32_t t0, t1, *p;

	for (p = v; p != &v[50]; p += 2) {
		//	uses bitmanip SHFL with immediate 15, which is pseudo-op "zip"
		t0 = _rv32_zip(p[0]);
		t1 = _rv32_zip(p[1]);
		p[0] = ((t1 & 0x55555555) << 1) | (t0 & 0x55555555);
		p[1] = ((t0 & 0xAAAAAAAA) >> 1) | (t1 & 0xAAAAAAAA);
	}
}

//	Keccak-p[1600,24](S)

static void riscv_KeccakF1600(uint64_t s[5][5])
{
	//	round constants (interleaved)

	const uint32_t rc[48] = {
		0x00000001, 0x00000000, 0x00000000, 0x00000089, 0x00000000,
		0x8000008B, 0x00000000, 0x80008080, 0x00000001, 0x0000008B,
		0x00000001, 0x00008000, 0x00000001, 0x80008088, 0x00000001,
		0x80000082, 0x00000000, 0x0000000B, 0x00000000, 0x0000000A,
		0x00000001, 0x00008082, 0x00000000, 0x00008003, 0x00000001,
		0x0000808B, 0x00000001, 0x8000000B, 0x00000001, 0x8000008A,
		0x00000001, 0x80000081, 0x00000000, 0x80000081, 0x00000000,
		0x80000008, 0x00000000, 0x00000083, 0x00000000, 0x80008003,
		0x00000001, 0x80008088, 0x00000000, 0x80000088, 0x00000001,
		0x00008000, 0x00000000, 0x80008082
	};

	uint32_t t0, t1, t2, t3, t4, t5, t6, t7, t8, t9;
	uint32_t u0, u1, u2, u3;
	const uint32_t *q;
	uint32_t *p;
	uint32_t *v = (uint32_t *) s;

	//	64-bit word even/odd bit split for the entire state ("un-interleave")
	//	we can have this outside the function for multi-block processing

	sha3_f1600_rvb32_split(v);

	//	(passed between rounds, initial load)

	u0 = v[40];
	u1 = v[41];
	t2 = v[42];
	t3 = v[43];
	t4 = v[44];
	t5 = v[45];
	t6 = v[46];
	t7 = v[47];
	t8 = v[48];
	t9 = v[49];

	//	24 rounds

	for (q = rc; q != &rc[48]; q += 2) {

		//	Theta

		for (p = v; p != &v[40]; p += 10) { //	(4 iterations)
			u0 = u0 ^ p[0];
			u1 = u1 ^ p[1];
			t2 = t2 ^ p[2];
			t3 = t3 ^ p[3];
			t4 = t4 ^ p[4];
			t5 = t5 ^ p[5];
			t6 = t6 ^ p[6];
			t7 = t7 ^ p[7];
			t8 = t8 ^ p[8];
			t9 = t9 ^ p[9];
		}

		t0 = u0 ^ _rv32_ror(t5, 31);
		t1 = u1 ^ t4;
		t4 = t4 ^ _rv32_ror(t9, 31);
		t5 = t5 ^ t8;
		t8 = t8 ^ _rv32_ror(t3, 31);
		t9 = t9 ^ t2;
		t2 = t2 ^ _rv32_ror(t7, 31);
		t3 = t3 ^ t6;
		t6 = t6 ^ _rv32_ror(u1, 31);
		t7 = t7 ^ u0;

		//	(Theta) Rho Pi

		u0 = v[0] ^ t8;
		u1 = v[1] ^ t9;
		v[0] = u0;
		v[1] = u1;
		u2 = v[2] ^ t0;
		u3 = v[3] ^ t1;
		u0 = v[12] ^ t0;
		u1 = v[13] ^ t1;
		v[2] = _rv32_ror(u0, 10);
		v[3] = _rv32_ror(u1, 10);
		u0 = v[18] ^ t6;
		u1 = v[19] ^ t7;
		v[12] = _rv32_ror(u0, 22);
		v[13] = _rv32_ror(u1, 22);
		u0 = v[44] ^ t2;
		u1 = v[45] ^ t3;
		v[18] = _rv32_ror(u1, 1);
		v[19] = _rv32_ror(u0, 2);
		u0 = v[28] ^ t6;
		u1 = v[29] ^ t7;
		v[44] = _rv32_ror(u1, 12);
		v[45] = _rv32_ror(u0, 13);
		u0 = v[40] ^ t8;
		u1 = v[41] ^ t9;
		v[28] = _rv32_ror(u0, 23);
		v[29] = _rv32_ror(u1, 23);
		u0 = v[4] ^ t2;
		u1 = v[5] ^ t3;
		v[40] = _rv32_ror(u0, 1);
		v[41] = _rv32_ror(u1, 1);
		u0 = v[24] ^ t2;
		u1 = v[25] ^ t3;
		v[4] = _rv32_ror(u1, 10);
		v[5] = _rv32_ror(u0, 11);
		u0 = v[26] ^ t4;
		u1 = v[27] ^ t5;
		v[24] = _rv32_ror(u1, 19);
		v[25] = _rv32_ror(u0, 20);
		u0 = v[38] ^ t6;
		u1 = v[39] ^ t7;
		v[26] = _rv32_ror(u0, 28);
		v[27] = _rv32_ror(u1, 28);
		u0 = v[46] ^ t4;
		u1 = v[47] ^ t5;
		v[38] = _rv32_ror(u0, 4);
		v[39] = _rv32_ror(u1, 4);
		u0 = v[30] ^ t8;
		u1 = v[31] ^ t9;
		v[46] = _rv32_ror(u1, 11);
		v[47] = _rv32_ror(u0, 12);
		u0 = v[8] ^ t6;
		u1 = v[9] ^ t7;
		v[30] = _rv32_ror(u1, 18);
		v[31] = _rv32_ror(u0, 19);
		u0 = v[48] ^ t6;
		u1 = v[49] ^ t7;
		v[8] = _rv32_ror(u0, 25);
		v[9] = _rv32_ror(u1, 25);
		u0 = v[42] ^ t0;
		u1 = v[43] ^ t1;
		v[48] = _rv32_ror(u0, 31);
		v[49] = _rv32_ror(u1, 31);
		u0 = v[16] ^ t4;
		u1 = v[17] ^ t5;
		v[42] = _rv32_ror(u1, 4);
		v[43] = _rv32_ror(u0, 5);
		u0 = v[32] ^ t0;
		u1 = v[33] ^ t1;
		v[16] = _rv32_ror(u1, 9);
		v[17] = _rv32_ror(u0, 10);
		u0 = v[10] ^ t8;
		u1 = v[11] ^ t9;
		v[32] = _rv32_ror(u0, 14);
		v[33] = _rv32_ror(u1, 14);
		u0 = v[6] ^ t4;
		u1 = v[7] ^ t5;
		v[10] = _rv32_ror(u0, 18);
		v[11] = _rv32_ror(u1, 18);
		u0 = v[36] ^ t4;
		u1 = v[37] ^ t5;
		v[6] = _rv32_ror(u1, 21);
		v[7] = _rv32_ror(u0, 22);
		u0 = v[34] ^ t2;
		u1 = v[35] ^ t3;
		v[36] = _rv32_ror(u1, 24);
		v[37] = _rv32_ror(u0, 25);
		u0 = v[22] ^ t0;
		u1 = v[23] ^ t1;
		v[34] = _rv32_ror(u0, 27);
		v[35] = _rv32_ror(u1, 27);
		u0 = v[14] ^ t2;
		u1 = v[15] ^ t3;
		v[22] = _rv32_ror(u0, 29);
		v[23] = _rv32_ror(u1, 29);
		u0 = v[20] ^ t8;
		u1 = v[21] ^ t9;
		v[14] = _rv32_ror(u1, 30);
		v[15] = _rv32_ror(u0, 31);
		v[20] = _rv32_ror(u3, 31);
		v[21] = u2;

		//	Chi

		for (p = v; p <= &v[40]; p += 10) { //	(5 iterations)
			u0 = p[0];
			t2 = p[2];
			t4 = p[4];
			t6 = p[6];
			t8 = p[8];
			u1 = p[1];
			t3 = p[3];
			t5 = p[5];
			t7 = p[7];
			t9 = p[9];
			t0 = _rv_andn(t8, t6);
			t1 = _rv_andn(t9, t7);
			t8 = t8 ^ _rv_andn(t2, u0);
			t9 = t9 ^ _rv_andn(t3, u1);
			t2 = t2 ^ _rv_andn(t6, t4);
			t3 = t3 ^ _rv_andn(t7, t5);
			t6 = t6 ^ _rv_andn(u0, t8);
			t7 = t7 ^ _rv_andn(u1, t9);
			u0 = u0 ^ _rv_andn(t4, t2);
			u1 = u1 ^ _rv_andn(t5, t3);
			t4 = t4 ^ t0;
			t5 = t5 ^ t1;
			p[0] = u0;
			p[2] = t2;
			p[4] = t4;
			p[6] = t6;
			p[8] = t8;
			p[1] = u1;
			p[3] = t3;
			p[5] = t5;
			p[7] = t7;
			p[9] = t9;
		}

		//	Iota

		t0 = v[0];
		t1 = v[1];
		v[0] = t0 ^ q[0];
		v[1] = t1 ^ q[1];
	}

	//	64-bit word even/odd bit state final join for output ("interleave")
	//	we can have this outside the function for multi-block processing

	sha3_f1600_rvb32_join(v);
}
#endif