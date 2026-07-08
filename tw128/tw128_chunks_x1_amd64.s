// In-register x1 duplex body kernel — AVX-512.
//
// Processes the full MSG_MORE-closed rho-blocks of a single duplex body
// (the trunk of a trunk-only message, chunk 0 when the ragged tail is too
// small to fuse, or a serial leaf) with the state resident in Z0-Z4 across
// all blocks, instead of a Go loop that XORs sigma into memory and
// round-trips the state through a p1600AVX512 call per 167 bytes.
//
// The permute reuses the CRYPTOGAMS-style X1 round macros from
// permute_amd64_avx512.h; the state layout returns to canonical rows after
// each even number of rounds, so the block I/O between permutes works on
// plain rows: lanes 0-19 are four 40-byte masked row loads/stores, and the
// 7-byte partial in lane 20 goes through a GPR. The partial-lane load reads
// 8 bytes; the 8th lies within the buffer because every block this kernel
// processes is followed by at least one more sigma byte (the caller handles
// the final block). The variable-length final block and its MSG_LAST close
// stay in Go.

//go:build !purego

#include "textflag.h"
#include "permute_amd64_avx512.h"

// X1_ENC_ROW encrypts one full 5-lane row at byte offset off: ct = pt ^ ks,
// state = pt. Z5/Z6 scratch; K6 = 5-lane mask; SI/DX walk per block.
#define X1_ENC_ROW(off, ZS) \
	VPXORQ	Z5, Z5, Z5; \
	VMOVDQU64	off(SI), K6, Z5; \
	VPXORQ	Z5, ZS, Z6; \
	VMOVDQU64	Z6, K6, off(DX); \
	VMOVDQA64	Z5, ZS

// X1_DEC_ROW is the decrypt mirror: the loaded row is ciphertext, the
// stored row is ct ^ ks, and the state absorbs the ciphertext (equal to the
// computed plaintext for full lanes).
#define X1_DEC_ROW(off, ZS) \
	VPXORQ	Z5, Z5, Z5; \
	VMOVDQU64	off(SI), K6, Z5; \
	VPXORQ	Z5, ZS, Z6; \
	VMOVDQU64	Z6, K6, off(DX); \
	VMOVDQA64	Z6, ZS

// X1_PERMUTE12 runs the 12-round permutation on Z0-Z4 (6 × even/odd).
#define X1_PERMUTE12(label) \
	LEAQ	tw128_avx512_x1_iotas+96(SB), R10; \
	MOVL	$6, AX; \
label: \
	X1_EVEN_ROUND; \
	X1_ODD_ROUND; \
	DECL	AX; \
	JNZ	label

// func encryptBodyBlocksAVX512(d *duplex, src, dst *byte, blocks uint64)
TEXT ·encryptBodyBlocksAVX512(SB), NOSPLIT, $0-32
	MOVQ	d+0(FP), DI
	X1_SETUP_MASKS
	LEAQ	tw128_avx512_x1_consts(SB), R8
	X1_LOAD_CONSTS
	X1_LOAD_STATE

	MOVQ	src+8(FP), SI
	MOVQ	dst+16(FP), DX
	MOVQ	blocks+24(FP), BX

	PCALIGN	$32
enc_body_avx512_loop:
	// Lanes 0-19: four full rows.
	X1_ENC_ROW(0, Z0)
	X1_ENC_ROW(40, Z1)
	X1_ENC_ROW(80, Z2)
	X1_ENC_ROW(120, Z3)

	// Lane 20 partial: read 8 bytes, mask the ciphertext to 7 bytes so byte
	// 7 keeps its keystream, store exactly 7 bytes, and fold in the combined
	// (MSG_MORE 0x1A | pad 0x80) suffix at byte 167.
	VMOVQ	X4, R9
	MOVQ	160(SI), R11
	MOVQ	R9, R12
	XORQ	R11, R12
	MOVQ	R12, R13
	SHLQ	$8, R13
	SHRQ	$8, R13
	XORQ	R13, R9
	MOVL	R12, 160(DX)
	SHRQ	$32, R12
	MOVW	R12, 164(DX)
	SHRQ	$16, R12
	MOVB	R12, 166(DX)
	MOVQ	$0x9A00000000000000, R13
	XORQ	R13, R9
	VPBROADCASTQ	R9, K1, Z4

	ADDQ	$167, SI
	ADDQ	$167, DX

	X1_PERMUTE12(enc_body_avx512_perm)

	DECQ	BX
	JNZ	enc_body_avx512_loop

	X1_STORE_STATE
	VZEROUPPER
	RET

// func decryptBodyBlocksAVX512(d *duplex, src, dst *byte, blocks uint64)
TEXT ·decryptBodyBlocksAVX512(SB), NOSPLIT, $0-32
	MOVQ	d+0(FP), DI
	X1_SETUP_MASKS
	LEAQ	tw128_avx512_x1_consts(SB), R8
	X1_LOAD_CONSTS
	X1_LOAD_STATE

	MOVQ	src+8(FP), SI
	MOVQ	dst+16(FP), DX
	MOVQ	blocks+24(FP), BX

	PCALIGN	$32
dec_body_avx512_loop:
	X1_DEC_ROW(0, Z0)
	X1_DEC_ROW(40, Z1)
	X1_DEC_ROW(80, Z2)
	X1_DEC_ROW(120, Z3)

	// Lane 20 partial: the loaded value is ciphertext; the state absorbs its
	// masked low 7 bytes and the stored plaintext is ct ^ ks.
	VMOVQ	X4, R9
	MOVQ	160(SI), R11
	MOVQ	R9, R12
	XORQ	R11, R12
	SHLQ	$8, R11
	SHRQ	$8, R11
	XORQ	R11, R9
	MOVL	R12, 160(DX)
	SHRQ	$32, R12
	MOVW	R12, 164(DX)
	SHRQ	$16, R12
	MOVB	R12, 166(DX)
	MOVQ	$0x9A00000000000000, R13
	XORQ	R13, R9
	VPBROADCASTQ	R9, K1, Z4

	ADDQ	$167, SI
	ADDQ	$167, DX

	X1_PERMUTE12(dec_body_avx512_perm)

	DECQ	BX
	JNZ	dec_body_avx512_loop

	X1_STORE_STATE
	VZEROUPPER
	RET
