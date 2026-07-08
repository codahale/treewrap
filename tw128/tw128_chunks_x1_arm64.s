// In-register x1 duplex body kernel — ARM64 NEON.
//
// Processes the full MSG_MORE-closed rho-blocks of a single duplex body
// (the trunk of a trunk-only message, or a serial leaf) with the 25-lane
// state resident in the low D lanes of V0-V24 across all blocks, instead of
// a Go loop that XORs sigma into memory and round-trips the whole state
// through a p1600 call per 167 bytes. The 12-round permute reuses
// KECCAK_12_ROUNDS with garbage in the upper D lanes, exactly like the x1
// permute in permute_x1_arm64.s.
//
// Each block is 20 full lanes plus the 7-byte partial in lane 20, closed
// with (MSG_MORE 0x1A | pad 0x80) = 0x9A at byte 167. The partial-lane load
// reads 8 bytes; the 8th lies within the buffer because every block this
// kernel processes is followed by at least one more sigma byte (the caller
// handles the final block). The variable-length final block and its
// MSG_LAST close stay in Go.

//go:build !purego

#include "textflag.h"
#include "permute_arm64.h"

// ENC_LANE_X1 encrypts one full lane: ct = pt ^ ks, state ^= ct. Src walks
// in R2, dst in R5; temps V25/V26.
#define ENC_LANE_X1(VK) \
	VLD1.P	8(R2), [V25.D1]; \
	VEOR	V25.B16, VK.B16, V26.B16; \
	VST1.P	[V26.D1], 8(R5); \
	VEOR	V26.B16, VK.B16, VK.B16

// DEC_LANE_X1 is the decrypt mirror: the state absorbs the loaded
// ciphertext and the stored plaintext is ct ^ ks.
#define DEC_LANE_X1(VK) \
	VLD1.P	8(R2), [V25.D1]; \
	VEOR	V25.B16, VK.B16, V26.B16; \
	VST1.P	[V26.D1], 8(R5); \
	VEOR	V25.B16, VK.B16, VK.B16

#define ENC_LANES20_X1 \
	ENC_LANE_X1(V0); \
	ENC_LANE_X1(V1); \
	ENC_LANE_X1(V2); \
	ENC_LANE_X1(V3); \
	ENC_LANE_X1(V4); \
	ENC_LANE_X1(V5); \
	ENC_LANE_X1(V6); \
	ENC_LANE_X1(V7); \
	ENC_LANE_X1(V8); \
	ENC_LANE_X1(V9); \
	ENC_LANE_X1(V10); \
	ENC_LANE_X1(V11); \
	ENC_LANE_X1(V12); \
	ENC_LANE_X1(V13); \
	ENC_LANE_X1(V14); \
	ENC_LANE_X1(V15); \
	ENC_LANE_X1(V16); \
	ENC_LANE_X1(V17); \
	ENC_LANE_X1(V18); \
	ENC_LANE_X1(V19)

#define DEC_LANES20_X1 \
	DEC_LANE_X1(V0); \
	DEC_LANE_X1(V1); \
	DEC_LANE_X1(V2); \
	DEC_LANE_X1(V3); \
	DEC_LANE_X1(V4); \
	DEC_LANE_X1(V5); \
	DEC_LANE_X1(V6); \
	DEC_LANE_X1(V7); \
	DEC_LANE_X1(V8); \
	DEC_LANE_X1(V9); \
	DEC_LANE_X1(V10); \
	DEC_LANE_X1(V11); \
	DEC_LANE_X1(V12); \
	DEC_LANE_X1(V13); \
	DEC_LANE_X1(V14); \
	DEC_LANE_X1(V15); \
	DEC_LANE_X1(V16); \
	DEC_LANE_X1(V17); \
	DEC_LANE_X1(V18); \
	DEC_LANE_X1(V19)

// ENC_PARTIAL7_X1 encrypts the 7-byte partial lane 20: it reads 8 bytes,
// masks the ciphertext to 7 bytes so byte 7 keeps its keystream, and stores
// exactly 7 bytes. Temps R9-R13.
#define ENC_PARTIAL7_X1 \
	VMOV	V20.D[0], R9; \
	MOVD	(R2), R10; \
	EOR	R9, R10, R11; \
	LSL	$8, R11, R12; \
	LSR	$8, R12, R12; \
	EOR	R12, R9, R9; \
	VMOV	R9, V20.D[0]; \
	MOVW	R11, (R5); \
	LSR	$32, R11, R13; \
	MOVH	R13, 4(R5); \
	LSR	$48, R11, R13; \
	MOVB	R13, 6(R5); \
	ADD	$7, R2; \
	ADD	$7, R5

// DEC_PARTIAL7_X1 decrypts the 7-byte partial lane 20: the state absorbs the
// masked ciphertext and the stored plaintext is ct ^ ks.
#define DEC_PARTIAL7_X1 \
	VMOV	V20.D[0], R9; \
	MOVD	(R2), R10; \
	EOR	R9, R10, R11; \
	LSL	$8, R10, R12; \
	LSR	$8, R12, R12; \
	EOR	R12, R9, R9; \
	VMOV	R9, V20.D[0]; \
	MOVW	R11, (R5); \
	LSR	$32, R11, R13; \
	MOVH	R13, 4(R5); \
	LSR	$48, R11, R13; \
	MOVB	R13, 6(R5); \
	ADD	$7, R2; \
	ADD	$7, R5

// MSGMORE_PERMUTE_X1 XORs (MSG_MORE 0x1A | pad 0x80) = 0x9A at byte 167 and
// runs the 12-round permutation. The upper D lanes carry garbage.
#define MSGMORE_PERMUTE_X1 \
	MOVD	$0x9A00000000000000, R9; \
	VDUP	R9, V25.D2; \
	VEOR	V25.B16, V20.B16, V20.B16; \
	MOVD	$tw128_round_consts(SB), R1; \
	ADD	$96, R1; \
	KECCAK_12_ROUNDS

#define LOAD25_X1(BASE) \
	VLD1.P	32(BASE), [V0.D1, V1.D1, V2.D1, V3.D1]; \
	VLD1.P	32(BASE), [V4.D1, V5.D1, V6.D1, V7.D1]; \
	VLD1.P	32(BASE), [V8.D1, V9.D1, V10.D1, V11.D1]; \
	VLD1.P	32(BASE), [V12.D1, V13.D1, V14.D1, V15.D1]; \
	VLD1.P	32(BASE), [V16.D1, V17.D1, V18.D1, V19.D1]; \
	VLD1.P	32(BASE), [V20.D1, V21.D1, V22.D1, V23.D1]; \
	VLD1	(BASE), [V24.D1]

#define STORE25_X1(BASE) \
	VST1.P	[V0.D1, V1.D1, V2.D1, V3.D1], 32(BASE); \
	VST1.P	[V4.D1, V5.D1, V6.D1, V7.D1], 32(BASE); \
	VST1.P	[V8.D1, V9.D1, V10.D1, V11.D1], 32(BASE); \
	VST1.P	[V12.D1, V13.D1, V14.D1, V15.D1], 32(BASE); \
	VST1.P	[V16.D1, V17.D1, V18.D1, V19.D1], 32(BASE); \
	VST1.P	[V20.D1, V21.D1, V22.D1, V23.D1], 32(BASE); \
	VST1	[V24.D1], (BASE)

// func encryptBodyBlocksARM64(d *duplex, src, dst *byte, blocks uint64)
TEXT ·encryptBodyBlocksARM64(SB), NOSPLIT, $0-32
	MOVD	d+0(FP), R0
	LOAD25_X1(R0)
	MOVD	src+8(FP), R2
	MOVD	dst+16(FP), R5
	MOVD	blocks+24(FP), R4

enc_body_x1_loop:
	ENC_LANES20_X1
	ENC_PARTIAL7_X1
	MSGMORE_PERMUTE_X1

	SUBS	$1, R4
	BNE	enc_body_x1_loop

	MOVD	d+0(FP), R0
	STORE25_X1(R0)
	RET

// func decryptBodyBlocksARM64(d *duplex, src, dst *byte, blocks uint64)
TEXT ·decryptBodyBlocksARM64(SB), NOSPLIT, $0-32
	MOVD	d+0(FP), R0
	LOAD25_X1(R0)
	MOVD	src+8(FP), R2
	MOVD	dst+16(FP), R5
	MOVD	blocks+24(FP), R4

dec_body_x1_loop:
	DEC_LANES20_X1
	DEC_PARTIAL7_X1
	MSGMORE_PERMUTE_X1

	SUBS	$1, R4
	BNE	dec_body_x1_loop

	MOVD	d+0(FP), R0
	STORE25_X1(R0)
	RET
