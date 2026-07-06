// Transposed AVX-512 steady-state chunk kernels. The per-lane gather/scatter of
// the plain AVX-512 body is replaced by contiguous loads plus an in-register 8x8
// transpose (and its inverse on output): lanes 0..19 of all eight chunks are
// loaded chunk-major, transposed to lane-major, absorbed, transposed back, and
// stored. Lane 20 (the 7-byte partial) stays on a single masked gather. This
// trades the gather's poor throughput and cold-memory stalls for prefetcher-
// friendly sequential access.
//
// The 12-round permutation and the tail block / tag extraction are shared with
// the rest of the package (permute_amd64_avx512.h, finish{Encrypt,Decrypt}LeafBatch8).

//go:build !purego

#include "textflag.h"
#include "permute_amd64_avx512.h"

// TRANSPOSE4X4 transposes the 4x4 qword tile in YMM regs A,B,C,D in place using
// temps T0..T3. Involutory: applying it twice is the identity. After it, for
// inputs {row r} it holds {col r}. Uses Go (reversed) operand order.
// EVEX forms (VSHUFI64X2, not VEX VPERM2I128) so YMM16-31 are encodable;
// $0/$3 select the low/high 128-bit lanes equivalently to VPERM2I128 $0x20/$0x31.
#define TRANSPOSE4X4(A, B, C, D, T0, T1, T2, T3) \
	VPUNPCKLQDQ	B, A, T0; \
	VPUNPCKHQDQ	B, A, T1; \
	VPUNPCKLQDQ	D, C, T2; \
	VPUNPCKHQDQ	D, C, T3; \
	VSHUFI64X2	$0, T2, T0, A; \
	VSHUFI64X2	$0, T3, T1, B; \
	VSHUFI64X2	$3, T2, T0, C; \
	VSHUFI64X2	$3, T3, T1, D

// SPILL_NONTILE / RELOAD_NONTILE save and restore the five lanes the transposed
// kernel uses as scratch (lane 20 plus the four capacity lanes 21..24), which
// are not touched while absorbing lanes 0..19. Defined before any TEXT so vet's
// asmdecl does not bind their SP offsets to a preceding function's frame.
#define SPILL_NONTILE \
	VMOVDQU64	Z20, 0(SP); \
	VMOVDQU64	Z21, 64(SP); \
	VMOVDQU64	Z22, 128(SP); \
	VMOVDQU64	Z23, 192(SP); \
	VMOVDQU64	Z24, 256(SP)

#define RELOAD_NONTILE \
	VMOVDQU64	0(SP), Z20; \
	VMOVDQU64	64(SP), Z21; \
	VMOVDQU64	128(SP), Z22; \
	VMOVDQU64	192(SP), Z23; \
	VMOVDQU64	256(SP), Z24

// TILE_IN loads and transposes lane-tile T (lanes 4T..4T+3) for all 8 chunks
// into lane-major ZMM Z20..Z23 (Z(20+k) = lane 4T+k = {c0..c7}). BX = block src,
// disp = constant chunk offset j*8183 plus T*32. Uses Y20..Y31 as scratch.
#define TILE_IN(T) \
	VMOVDQU64	(0*8183+T*32)(BX), Y20; \
	VMOVDQU64	(1*8183+T*32)(BX), Y21; \
	VMOVDQU64	(2*8183+T*32)(BX), Y22; \
	VMOVDQU64	(3*8183+T*32)(BX), Y23; \
	TRANSPOSE4X4(Y20, Y21, Y22, Y23, Y24, Y25, Y26, Y27); \
	VMOVDQU64	(4*8183+T*32)(BX), Y28; \
	VMOVDQU64	(5*8183+T*32)(BX), Y29; \
	VMOVDQU64	(6*8183+T*32)(BX), Y30; \
	VMOVDQU64	(7*8183+T*32)(BX), Y31; \
	TRANSPOSE4X4(Y28, Y29, Y30, Y31, Y24, Y25, Y26, Y27); \
	VINSERTI64X4	$1, Y28, Z20, Z20; \
	VINSERTI64X4	$1, Y29, Z21, Z21; \
	VINSERTI64X4	$1, Y30, Z22, Z22; \
	VINSERTI64X4	$1, Y31, Z23, Z23

// TILE_OUT transposes ct lanes in Z24..Z27 (lane-major) back to chunk-major and
// stores each chunk's 4 lanes contiguously at (j*8183+T*32)(R14). Uses Y20..Y31.
#define TILE_OUT(T) \
	VEXTRACTI64X4	$1, Z24, Y20; \
	VEXTRACTI64X4	$1, Z25, Y21; \
	VEXTRACTI64X4	$1, Z26, Y22; \
	VEXTRACTI64X4	$1, Z27, Y23; \
	TRANSPOSE4X4(Y24, Y25, Y26, Y27, Y28, Y29, Y30, Y31); \
	VMOVDQU64	Y24, (0*8183+T*32)(R14); \
	VMOVDQU64	Y25, (1*8183+T*32)(R14); \
	VMOVDQU64	Y26, (2*8183+T*32)(R14); \
	VMOVDQU64	Y27, (3*8183+T*32)(R14); \
	TRANSPOSE4X4(Y20, Y21, Y22, Y23, Y28, Y29, Y30, Y31); \
	VMOVDQU64	Y20, (4*8183+T*32)(R14); \
	VMOVDQU64	Y21, (5*8183+T*32)(R14); \
	VMOVDQU64	Y22, (6*8183+T*32)(R14); \
	VMOVDQU64	Y23, (7*8183+T*32)(R14)

// TILE_ABSORB computes ct = pt ^ state and state ^= ct for the 4 lanes of tile T
// (encrypt). pt lanes in Z20..Z23, state lanes Z(4T+0..3); leaves ct in Z24..Z27.
#define TILE_ABSORB(L0, L1, L2, L3) \
	VPXORQ	Z20, L0, Z24; VPXORQ Z24, L0, L0; \
	VPXORQ	Z21, L1, Z25; VPXORQ Z25, L1, L1; \
	VPXORQ	Z22, L2, Z26; VPXORQ Z26, L2, L2; \
	VPXORQ	Z23, L3, Z27; VPXORQ Z27, L3, L3

// TILE_ABSORB_DEC is the decrypt counterpart: in = ct (Z20..Z23), out = pt
// (Z24..Z27), state ^= ct. For decrypt pt == ks^ct == state^ct, so the output
// and the new state lane are the same value (second XOR uses the ct input).
#define TILE_ABSORB_DEC(L0, L1, L2, L3) \
	VPXORQ	Z20, L0, Z24; VPXORQ Z20, L0, L0; \
	VPXORQ	Z21, L1, Z25; VPXORQ Z21, L1, L1; \
	VPXORQ	Z22, L2, Z26; VPXORQ Z22, L2, L2; \
	VPXORQ	Z23, L3, Z27; VPXORQ Z23, L3, L3


// func encryptChunksBodyAVX512T(s *state8, src, dst *byte)
//
// Transposed steady-state kernel: lanes 0..19 are absorbed via contiguous loads
// + an in-register transpose (no gather); lane 20 (the 7-byte partial) stays on a
// single masked gather. Processes the 48 MSG_MORE rho-blocks and stores the
// 8-way state back into s; the tail block and tags are completed in Go.
//
// Frame: 320 bytes spill (Z20..Z24) + 64-byte gather index vector.
TEXT ·encryptChunksBodyAVX512T(SB), $384-24
	MOVQ	s+0(FP), AX
	MOVQ	src+8(FP), BX
	MOVQ	dst+16(FP), R14

	MOVQ	$0, 320(SP)
	MOVQ	$8183, 328(SP)
	MOVQ	$16366, 336(SP)
	MOVQ	$24549, 344(SP)
	MOVQ	$32732, 352(SP)
	MOVQ	$40915, 360(SP)
	MOVQ	$49098, 368(SP)
	MOVQ	$57281, 376(SP)

	VMOVDQU64	0*64(AX), Z0
	VMOVDQU64	1*64(AX), Z1
	VMOVDQU64	2*64(AX), Z2
	VMOVDQU64	3*64(AX), Z3
	VMOVDQU64	4*64(AX), Z4
	VMOVDQU64	5*64(AX), Z5
	VMOVDQU64	6*64(AX), Z6
	VMOVDQU64	7*64(AX), Z7
	VMOVDQU64	8*64(AX), Z8
	VMOVDQU64	9*64(AX), Z9
	VMOVDQU64	10*64(AX), Z10
	VMOVDQU64	11*64(AX), Z11
	VMOVDQU64	12*64(AX), Z12
	VMOVDQU64	13*64(AX), Z13
	VMOVDQU64	14*64(AX), Z14
	VMOVDQU64	15*64(AX), Z15
	VMOVDQU64	16*64(AX), Z16
	VMOVDQU64	17*64(AX), Z17
	VMOVDQU64	18*64(AX), Z18
	VMOVDQU64	19*64(AX), Z19
	VMOVDQU64	20*64(AX), Z20
	VMOVDQU64	21*64(AX), Z21
	VMOVDQU64	22*64(AX), Z22
	VMOVDQU64	23*64(AX), Z23
	VMOVDQU64	24*64(AX), Z24

	MOVQ	$0x00FFFFFFFFFFFFFF, R13
	MOVQ	$0x9A00000000000000, DI

	MOVQ	$48, R12

tw128_enc_avx512t_loop:
	SPILL_NONTILE

	TILE_IN(0)
	TILE_ABSORB(Z0, Z1, Z2, Z3)
	TILE_OUT(0)
	TILE_IN(1)
	TILE_ABSORB(Z4, Z5, Z6, Z7)
	TILE_OUT(1)
	TILE_IN(2)
	TILE_ABSORB(Z8, Z9, Z10, Z11)
	TILE_OUT(2)
	TILE_IN(3)
	TILE_ABSORB(Z12, Z13, Z14, Z15)
	TILE_OUT(3)
	TILE_IN(4)
	TILE_ABSORB(Z16, Z17, Z18, Z19)
	TILE_OUT(4)

	RELOAD_NONTILE

	// Lane 20: 7-byte partial via masked gather/scatter.
	VMOVDQU64	320(SP), Z28
	VPBROADCASTQ	R13, Z27
	KXNORB	K1, K1, K1
	VPGATHERQQ	160(BX)(Z28*1), K1, Z25
	VPXORQ	Z25, Z20, Z26
	VPANDQ	Z27, Z26, Z26
	// The scatter writes whole qwords, so byte 7 of the stored value must be
	// the original gathered byte (the next block's first source byte): a
	// fully-overlapping dst would otherwise be clobbered before it is read.
	VPANDNQ	Z25, Z27, Z29
	VPORQ	Z26, Z29, Z29
	KXNORB	K1, K1, K1
	VPSCATTERQQ	Z29, K1, 160(R14)(Z28*1)
	VPXORQ	Z26, Z20, Z20

	// MSG_MORE close at byte 167 (lane 20, byte 7).
	VPBROADCASTQ	DI, Z26
	VPXORQ	Z26, Z20, Z20

	LEAQ	tw128_round_consts_2x+192(SB), R11
	X8_4ROUNDS_AVX512(0, 16, 32, 48)
	X8_4ROUNDS_AVX512(64, 80, 96, 112)
	X8_4ROUNDS_AVX512(128, 144, 160, 176)

	ADDQ	$167, BX
	ADDQ	$167, R14
	SUBQ	$1, R12
	JNZ	tw128_enc_avx512t_loop

	VMOVDQU64	Z0, 0*64(AX)
	VMOVDQU64	Z1, 1*64(AX)
	VMOVDQU64	Z2, 2*64(AX)
	VMOVDQU64	Z3, 3*64(AX)
	VMOVDQU64	Z4, 4*64(AX)
	VMOVDQU64	Z5, 5*64(AX)
	VMOVDQU64	Z6, 6*64(AX)
	VMOVDQU64	Z7, 7*64(AX)
	VMOVDQU64	Z8, 8*64(AX)
	VMOVDQU64	Z9, 9*64(AX)
	VMOVDQU64	Z10, 10*64(AX)
	VMOVDQU64	Z11, 11*64(AX)
	VMOVDQU64	Z12, 12*64(AX)
	VMOVDQU64	Z13, 13*64(AX)
	VMOVDQU64	Z14, 14*64(AX)
	VMOVDQU64	Z15, 15*64(AX)
	VMOVDQU64	Z16, 16*64(AX)
	VMOVDQU64	Z17, 17*64(AX)
	VMOVDQU64	Z18, 18*64(AX)
	VMOVDQU64	Z19, 19*64(AX)
	VMOVDQU64	Z20, 20*64(AX)
	VMOVDQU64	Z21, 21*64(AX)
	VMOVDQU64	Z22, 22*64(AX)
	VMOVDQU64	Z23, 23*64(AX)
	VMOVDQU64	Z24, 24*64(AX)

	VZEROUPPER
	RET


// func decryptChunksBodyAVX512T(s *state8, src, dst *byte)
//
// Decrypt counterpart of encryptChunksBodyAVX512T.
TEXT ·decryptChunksBodyAVX512T(SB), $384-24
	MOVQ	s+0(FP), AX
	MOVQ	src+8(FP), BX
	MOVQ	dst+16(FP), R14

	MOVQ	$0, 320(SP)
	MOVQ	$8183, 328(SP)
	MOVQ	$16366, 336(SP)
	MOVQ	$24549, 344(SP)
	MOVQ	$32732, 352(SP)
	MOVQ	$40915, 360(SP)
	MOVQ	$49098, 368(SP)
	MOVQ	$57281, 376(SP)

	VMOVDQU64	0*64(AX), Z0
	VMOVDQU64	1*64(AX), Z1
	VMOVDQU64	2*64(AX), Z2
	VMOVDQU64	3*64(AX), Z3
	VMOVDQU64	4*64(AX), Z4
	VMOVDQU64	5*64(AX), Z5
	VMOVDQU64	6*64(AX), Z6
	VMOVDQU64	7*64(AX), Z7
	VMOVDQU64	8*64(AX), Z8
	VMOVDQU64	9*64(AX), Z9
	VMOVDQU64	10*64(AX), Z10
	VMOVDQU64	11*64(AX), Z11
	VMOVDQU64	12*64(AX), Z12
	VMOVDQU64	13*64(AX), Z13
	VMOVDQU64	14*64(AX), Z14
	VMOVDQU64	15*64(AX), Z15
	VMOVDQU64	16*64(AX), Z16
	VMOVDQU64	17*64(AX), Z17
	VMOVDQU64	18*64(AX), Z18
	VMOVDQU64	19*64(AX), Z19
	VMOVDQU64	20*64(AX), Z20
	VMOVDQU64	21*64(AX), Z21
	VMOVDQU64	22*64(AX), Z22
	VMOVDQU64	23*64(AX), Z23
	VMOVDQU64	24*64(AX), Z24

	MOVQ	$0x00FFFFFFFFFFFFFF, R13
	MOVQ	$0x9A00000000000000, DI

	MOVQ	$48, R12

tw128_dec_avx512t_loop:
	SPILL_NONTILE

	TILE_IN(0)
	TILE_ABSORB_DEC(Z0, Z1, Z2, Z3)
	TILE_OUT(0)
	TILE_IN(1)
	TILE_ABSORB_DEC(Z4, Z5, Z6, Z7)
	TILE_OUT(1)
	TILE_IN(2)
	TILE_ABSORB_DEC(Z8, Z9, Z10, Z11)
	TILE_OUT(2)
	TILE_IN(3)
	TILE_ABSORB_DEC(Z12, Z13, Z14, Z15)
	TILE_OUT(3)
	TILE_IN(4)
	TILE_ABSORB_DEC(Z16, Z17, Z18, Z19)
	TILE_OUT(4)

	RELOAD_NONTILE

	// Lane 20: 7-byte partial via masked gather/scatter (decrypt).
	VMOVDQU64	320(SP), Z28
	VPBROADCASTQ	R13, Z27
	KXNORB	K1, K1, K1
	VPGATHERQQ	160(BX)(Z28*1), K1, Z25
	VPXORQ	Z25, Z20, Z26
	VPANDQ	Z27, Z26, Z26
	// As in the encrypt kernel: byte 7 of the scattered qword carries the
	// original gathered byte so a fully-overlapping dst is not corrupted.
	VPANDNQ	Z25, Z27, Z29
	VPORQ	Z26, Z29, Z29
	VPANDQ	Z27, Z25, Z25
	KXNORB	K1, K1, K1
	VPSCATTERQQ	Z29, K1, 160(R14)(Z28*1)
	VPXORQ	Z25, Z20, Z20

	VPBROADCASTQ	DI, Z26
	VPXORQ	Z26, Z20, Z20

	LEAQ	tw128_round_consts_2x+192(SB), R11
	X8_4ROUNDS_AVX512(0, 16, 32, 48)
	X8_4ROUNDS_AVX512(64, 80, 96, 112)
	X8_4ROUNDS_AVX512(128, 144, 160, 176)

	ADDQ	$167, BX
	ADDQ	$167, R14
	SUBQ	$1, R12
	JNZ	tw128_dec_avx512t_loop

	VMOVDQU64	Z0, 0*64(AX)
	VMOVDQU64	Z1, 1*64(AX)
	VMOVDQU64	Z2, 2*64(AX)
	VMOVDQU64	Z3, 3*64(AX)
	VMOVDQU64	Z4, 4*64(AX)
	VMOVDQU64	Z5, 5*64(AX)
	VMOVDQU64	Z6, 6*64(AX)
	VMOVDQU64	Z7, 7*64(AX)
	VMOVDQU64	Z8, 8*64(AX)
	VMOVDQU64	Z9, 9*64(AX)
	VMOVDQU64	Z10, 10*64(AX)
	VMOVDQU64	Z11, 11*64(AX)
	VMOVDQU64	Z12, 12*64(AX)
	VMOVDQU64	Z13, 13*64(AX)
	VMOVDQU64	Z14, 14*64(AX)
	VMOVDQU64	Z15, 15*64(AX)
	VMOVDQU64	Z16, 16*64(AX)
	VMOVDQU64	Z17, 17*64(AX)
	VMOVDQU64	Z18, 18*64(AX)
	VMOVDQU64	Z19, 19*64(AX)
	VMOVDQU64	Z20, 20*64(AX)
	VMOVDQU64	Z21, 21*64(AX)
	VMOVDQU64	Z22, 22*64(AX)
	VMOVDQU64	Z23, 23*64(AX)
	VMOVDQU64	Z24, 24*64(AX)

	VZEROUPPER
	RET
