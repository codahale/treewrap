// Hybrid scalar/NEON 5-chunk kernel — ARM64.
//
// Processes 5 × 8183-byte chunks per call: chunks 0-3 as two sequential
// 2-wide NEON pair passes (instances 0,1 then 2,3 of the state8), and chunk 4
// on the scalar pipes, woven into the NEON round stream at a 1:2 rate (six
// scalar rounds inside each 12-round NEON permute, so one scalar block
// completes per two NEON block iterations). The two passes are 2 × 49 = 98
// NEON iterations, during which the scalar lane completes exactly 49 blocks —
// one chunk. The scalar stream executes almost entirely in the shadow of the
// NEON stream (measured ~3ns per scalar permute on Apple M4), so the fifth
// chunk is nearly free.
//
// NEON iterations alternate two phases: A hosts the scalar block I/O plus
// scalar rounds 0-5, B hosts scalar rounds 6-11. 49 is odd, so the phase
// alternation crosses the pass boundary: the pass-1 epilogue (tag extraction
// and the pair state swap) runs between a scalar block's A and B phases,
// touching only R22/R23 and the vector registers.
//
// Scalar state register map and SROUND/SCALAR_* macros: see
// permute_scalar_arm64.h. The NEON pair I/O uses R22-R25 as its four walking
// pointers (loaded from and stored to the frame each iteration) so the scalar
// state can occupy the registers the non-hybrid kernels use for pointers.
//
// Frame: 0=src0, 8=src1, 16=dst0, 24=dst1, 32/40/48/56/64=spilled scalar
// lanes (fixed by permute_scalar_arm64.h), 72=scalar src, 80=scalar dst,
// 88=unit counter, 96=s, 104=d, 112=tags.

//go:build !purego

#include "textflag.h"
#include "permute_arm64.h"
#include "permute_scalar_arm64.h"

// ENC_LANE_X5 encrypts one full lane (state register VK) for the NEON pair;
// the walking pointers are R22/R23 (src) and R24/R25 (dst).
#define ENC_LANE_X5(VK) \
	VLD1	(R22), [V25.D1]; ADD $8, R22; VLD1 (R23), [V26.D1]; ADD $8, R23; VZIP1 V26.D2, V25.D2, V25.D2; VEOR V25.B16, VK.B16, V26.B16; VEOR V26.B16, VK.B16, VK.B16; VST1 [V26.D1], (R24); ADD $8, R24; VDUP V26.D[1], V27.D2; VST1 [V27.D1], (R25); ADD $8, R25

// DEC_LANE_X5 is the decrypt mirror: the state absorbs the loaded ciphertext.
#define DEC_LANE_X5(VK) \
	VLD1	(R22), [V25.D1]; ADD $8, R22; VLD1 (R23), [V26.D1]; ADD $8, R23; VZIP1 V26.D2, V25.D2, V25.D2; VEOR V25.B16, VK.B16, V26.B16; VEOR V25.B16, VK.B16, VK.B16; VST1 [V26.D1], (R24); ADD $8, R24; VDUP V26.D[1], V27.D2; VST1 [V27.D1], (R25); ADD $8, R25

#define ENC_LANES20_X5 \
	ENC_LANE_X5(V0); \
	ENC_LANE_X5(V1); \
	ENC_LANE_X5(V2); \
	ENC_LANE_X5(V3); \
	ENC_LANE_X5(V4); \
	ENC_LANE_X5(V5); \
	ENC_LANE_X5(V6); \
	ENC_LANE_X5(V7); \
	ENC_LANE_X5(V8); \
	ENC_LANE_X5(V9); \
	ENC_LANE_X5(V10); \
	ENC_LANE_X5(V11); \
	ENC_LANE_X5(V12); \
	ENC_LANE_X5(V13); \
	ENC_LANE_X5(V14); \
	ENC_LANE_X5(V15); \
	ENC_LANE_X5(V16); \
	ENC_LANE_X5(V17); \
	ENC_LANE_X5(V18); \
	ENC_LANE_X5(V19)

#define DEC_LANES20_X5 \
	DEC_LANE_X5(V0); \
	DEC_LANE_X5(V1); \
	DEC_LANE_X5(V2); \
	DEC_LANE_X5(V3); \
	DEC_LANE_X5(V4); \
	DEC_LANE_X5(V5); \
	DEC_LANE_X5(V6); \
	DEC_LANE_X5(V7); \
	DEC_LANE_X5(V8); \
	DEC_LANE_X5(V9); \
	DEC_LANE_X5(V10); \
	DEC_LANE_X5(V11); \
	DEC_LANE_X5(V12); \
	DEC_LANE_X5(V13); \
	DEC_LANE_X5(V14); \
	DEC_LANE_X5(V15); \
	DEC_LANE_X5(V16); \
	DEC_LANE_X5(V17); \
	DEC_LANE_X5(V18); \
	DEC_LANE_X5(V19)

// ENC_PARTIAL7_X5 encrypts the 7-byte partial lane 20 for both NEON
// instances. It advances and stashes all four pointers, then works in
// R22/R23/R26 with the masked ciphertexts staged in V25 and absorbed with a
// single VEOR. loadA/loadB inject the source-load variant: direct 8-byte
// loads for MSG_MORE blocks (the 8th byte is within the chunk), or the
// shifted load ending at the last chunk byte for the final block.
#define PARTIAL7_HEAD \
	ADD	$7, R22; \
	ADD	$7, R23; \
	STP	(R22, R23), 0(RSP)

#define LOAD_TAIL8_MORE \
	MOVD	-7(R22), R26; \
	MOVD	-7(R23), R22

#define LOAD_TAIL8_LAST \
	MOVD	-8(R22), R26; \
	LSR	$8, R26, R26; \
	MOVD	-8(R23), R22; \
	LSR	$8, R22, R22

#define ENC_PARTIAL7_X5_BODY \
	VMOV	V20.D[0], R23; \
	EOR	R26, R23, R23; \
	AND	$0x00FFFFFFFFFFFFFF, R23, R26; \
	VMOV	R26, V25.D[0]; \
	MOVW	R23, (R24); \
	LSR	$32, R23, R23; \
	MOVH	R23, 4(R24); \
	LSR	$16, R23, R23; \
	MOVB	R23, 6(R24); \
	ADD	$7, R24; \
	VMOV	V20.D[1], R23; \
	EOR	R22, R23, R23; \
	AND	$0x00FFFFFFFFFFFFFF, R23, R26; \
	VMOV	R26, V25.D[1]; \
	MOVW	R23, (R25); \
	LSR	$32, R23, R23; \
	MOVH	R23, 4(R25); \
	LSR	$16, R23, R23; \
	MOVB	R23, 6(R25); \
	ADD	$7, R25; \
	STP	(R24, R25), 16(RSP); \
	VEOR	V25.B16, V20.B16, V20.B16

// DEC_PARTIAL7_X5_BODY: the loaded value is the ciphertext; the state absorbs
// its masked low 7 bytes and the stored plaintext is ct ^ ks.
#define DEC_PARTIAL7_X5_BODY \
	VMOV	V20.D[0], R23; \
	EOR	R26, R23, R23; \
	AND	$0x00FFFFFFFFFFFFFF, R26, R26; \
	VMOV	R26, V25.D[0]; \
	MOVW	R23, (R24); \
	LSR	$32, R23, R23; \
	MOVH	R23, 4(R24); \
	LSR	$16, R23, R23; \
	MOVB	R23, 6(R24); \
	ADD	$7, R24; \
	VMOV	V20.D[1], R23; \
	EOR	R22, R23, R23; \
	AND	$0x00FFFFFFFFFFFFFF, R22, R26; \
	VMOV	R26, V25.D[1]; \
	MOVW	R23, (R25); \
	LSR	$32, R23, R23; \
	MOVH	R23, 4(R25); \
	LSR	$16, R23, R23; \
	MOVB	R23, 6(R25); \
	ADD	$7, R25; \
	STP	(R24, R25), 16(RSP); \
	VEOR	V25.B16, V20.B16, V20.B16

// SUFFIX_X5 XORs the combined suffix/pad byte at byte 167 of both NEON
// instances and resets the NEON round-constant pointer.
#define SUFFIX_X5(val) \
	MOVD	val, R22; \
	VDUP	R22, V25.D2; \
	VEOR	V25.B16, V20.B16, V20.B16; \
	MOVD	$tw128_round_consts(SB), R1; \
	ADD	$96, R1

// NEON block I/O variants: full pair-lane pass, partial lane, suffix, RC
// pointer reset. MSG_MORE and MSG_LAST for encrypt and decrypt.
#define NEON_IO_ENC_MORE \
	LDP	0(RSP), (R22, R23); \
	LDP	16(RSP), (R24, R25); \
	ENC_LANES20_X5; \
	PARTIAL7_HEAD; \
	LOAD_TAIL8_MORE; \
	ENC_PARTIAL7_X5_BODY; \
	SUFFIX_X5($0x9A00000000000000)

#define NEON_IO_ENC_LAST \
	LDP	0(RSP), (R22, R23); \
	LDP	16(RSP), (R24, R25); \
	ENC_LANES20_X5; \
	PARTIAL7_HEAD; \
	LOAD_TAIL8_LAST; \
	ENC_PARTIAL7_X5_BODY; \
	SUFFIX_X5($0x9E00000000000000)

#define NEON_IO_DEC_MORE \
	LDP	0(RSP), (R22, R23); \
	LDP	16(RSP), (R24, R25); \
	DEC_LANES20_X5; \
	PARTIAL7_HEAD; \
	LOAD_TAIL8_MORE; \
	DEC_PARTIAL7_X5_BODY; \
	SUFFIX_X5($0x9A00000000000000)

#define NEON_IO_DEC_LAST \
	LDP	0(RSP), (R22, R23); \
	LDP	16(RSP), (R24, R25); \
	DEC_LANES20_X5; \
	PARTIAL7_HEAD; \
	LOAD_TAIL8_LAST; \
	DEC_PARTIAL7_X5_BODY; \
	SUFFIX_X5($0x9E00000000000000)

// Scalar block I/O at the hybrid frame offsets (72=src, 80=dst).
#define SCALAR_IO_ENC_MORE \
	MOVD	72(RSP), R25; \
	MOVD	80(RSP), R26; \
	SCALAR_ENC_LANES19; \
	SCALAR_ENC_TAIL($0x9A00000000000000); \
	MOVD	R25, 72(RSP); \
	MOVD	R26, 80(RSP)

#define SCALAR_IO_ENC_LAST \
	MOVD	72(RSP), R25; \
	MOVD	80(RSP), R26; \
	SCALAR_ENC_LANES19; \
	SCALAR_ENC_TAIL_LAST($0x9E00000000000000); \
	MOVD	R25, 72(RSP); \
	MOVD	R26, 80(RSP)

#define SCALAR_IO_DEC_MORE \
	MOVD	72(RSP), R25; \
	MOVD	80(RSP), R26; \
	SCALAR_DEC_LANES19; \
	SCALAR_DEC_TAIL($0x9A00000000000000); \
	MOVD	R25, 72(RSP); \
	MOVD	R26, 80(RSP)

#define SCALAR_IO_DEC_LAST \
	MOVD	72(RSP), R25; \
	MOVD	80(RSP), R26; \
	SCALAR_DEC_LANES19; \
	SCALAR_DEC_TAIL_LAST($0x9E00000000000000); \
	MOVD	R25, 72(RSP); \
	MOVD	R26, 80(RSP)

// WEAVE_A runs the 12-round NEON permute with scalar rounds 0-5 woven in
// after every second NEON round; WEAVE_B hosts scalar rounds 6-11. Two
// consecutive weaves complete one scalar permute.
#define WEAVE_A \
	KECCAK_ROUND; \
	KECCAK_ROUND; \
	SROUND($0x000000008000808B); \
	KECCAK_ROUND; \
	KECCAK_ROUND; \
	SROUND($0x800000000000008B); \
	KECCAK_ROUND; \
	KECCAK_ROUND; \
	SROUND($0x8000000000008089); \
	KECCAK_ROUND; \
	KECCAK_ROUND; \
	SROUND($0x8000000000008003); \
	KECCAK_ROUND; \
	KECCAK_ROUND; \
	SROUND($0x8000000000008002); \
	KECCAK_ROUND; \
	KECCAK_ROUND; \
	SROUND($0x8000000000000080)

#define WEAVE_B \
	KECCAK_ROUND; \
	KECCAK_ROUND; \
	SROUND($0x000000000000800A); \
	KECCAK_ROUND; \
	KECCAK_ROUND; \
	SROUND($0x800000008000000A); \
	KECCAK_ROUND; \
	KECCAK_ROUND; \
	SROUND($0x8000000080008081); \
	KECCAK_ROUND; \
	KECCAK_ROUND; \
	SROUND($0x8000000000008080); \
	KECCAK_ROUND; \
	KECCAK_ROUND; \
	SROUND($0x0000000080000001); \
	KECCAK_ROUND; \
	KECCAK_ROUND; \
	SROUND($0x8000000080008008)

// EXTRACT_TAGS_X5 writes lanes 0-3 of both NEON instances to the tag buffer
// at R22 (64 bytes).
#define EXTRACT_TAGS_X5 \
	VST1	[V0.D1], (R22); ADD $8, R22; \
	VST1	[V1.D1], (R22); ADD $8, R22; \
	VST1	[V2.D1], (R22); ADD $8, R22; \
	VST1	[V3.D1], (R22); ADD $8, R22; \
	VDUP	V0.D[1], V25.D2; VST1 [V25.D1], (R22); ADD $8, R22; \
	VDUP	V1.D[1], V25.D2; VST1 [V25.D1], (R22); ADD $8, R22; \
	VDUP	V2.D[1], V25.D2; VST1 [V25.D1], (R22); ADD $8, R22; \
	VDUP	V3.D[1], V25.D2; VST1 [V25.D1], (R22)

// X5_PROLOGUE stashes the arguments, derives the five chunk pointers, and
// loads the scalar state and NEON pair (0,1).
#define X5_PROLOGUE \
	MOVD	s+0(FP), R22; \
	MOVD	R22, 96(RSP); \
	MOVD	d+8(FP), R22; \
	MOVD	R22, 104(RSP); \
	MOVD	tags+32(FP), R22; \
	MOVD	R22, 112(RSP); \
	MOVD	src+16(FP), R22; \
	ADD	$8183, R22, R23; \
	STP	(R22, R23), 0(RSP); \
	ADD	$32732, R22, R23; \
	MOVD	R23, 72(RSP); \
	MOVD	dst+24(FP), R22; \
	ADD	$8183, R22, R23; \
	STP	(R22, R23), 16(RSP); \
	ADD	$32732, R22, R23; \
	MOVD	R23, 80(RSP); \
	MOVD	104(RSP), R22; \
	SCALAR_LOAD_STATE; \
	MOVD	96(RSP), R22; \
	LOAD25_STRIDE(R22, 64)

// X5_PASS1_EPILOGUE extracts pair-1 tags, stores pair (0,1) back into s (for
// the lane-0 chunk-0 fusion contract), loads pair (2,3), and advances the
// NEON pointers to chunks 2 and 3. Runs between the A and B phases of scalar
// block 25; touches only R22/R23 and the vector registers.
#define X5_PASS1_EPILOGUE \
	MOVD	112(RSP), R22; \
	EXTRACT_TAGS_X5; \
	MOVD	96(RSP), R22; \
	STORE25_STRIDE(R22, 64); \
	MOVD	96(RSP), R22; \
	ADD	$16, R22; \
	LOAD25_STRIDE(R22, 64); \
	MOVD	8(RSP), R22; \
	ADD	$8183, R22, R23; \
	STP	(R22, R23), 0(RSP); \
	MOVD	24(RSP), R22; \
	ADD	$8183, R22, R23; \
	STP	(R22, R23), 16(RSP)

// X5_EPILOGUE extracts pair-2 tags (tags+64) and the scalar leaf tag
// (tags+128, scalar lanes 0-3).
#define X5_EPILOGUE \
	MOVD	112(RSP), R22; \
	ADD	$64, R22; \
	EXTRACT_TAGS_X5; \
	MOVD	112(RSP), R22; \
	MOVD	R0, 128(R22); \
	MOVD	64(RSP), R23; \
	MOVD	R23, 136(R22); \
	MOVD	R2, 144(R22); \
	MOVD	R3, 152(R22)

#define X5_COUNT(n) \
	MOVD	$n, R22; \
	MOVD	R22, 88(RSP)

#define X5_DEC_COUNT(label) \
	MOVD	88(RSP), R22; \
	SUB	$1, R22; \
	MOVD	R22, 88(RSP); \
	CBNZ	R22, label

// func encryptChunks5ARM64(s *state8, d *duplex, src, dst, tags *byte)
TEXT ·encryptChunks5ARM64(SB), NOSPLIT, $120-40
	X5_PROLOGUE

	// Pass 1, iterations 1-48: 24 (A,B) units over chunks 0,1; scalar
	// blocks 1-24 complete inside their units.
	X5_COUNT(24)
enc5_pass1_loop:
	NEON_IO_ENC_MORE
	SCALAR_IO_ENC_MORE
	WEAVE_A
	NEON_IO_ENC_MORE
	WEAVE_B
	X5_DEC_COUNT(enc5_pass1_loop)

	// Iteration 49: NEON MSG_LAST for chunks 0,1; scalar block 25 A-phase.
	NEON_IO_ENC_LAST
	SCALAR_IO_ENC_MORE
	WEAVE_A

	X5_PASS1_EPILOGUE

	// Iteration 50: first block of chunks 2,3; scalar block 25 B-phase.
	NEON_IO_ENC_MORE
	WEAVE_B

	// Pass 2, iterations 51-96: 23 units; scalar blocks 26-48.
	X5_COUNT(23)
enc5_pass2_loop:
	NEON_IO_ENC_MORE
	SCALAR_IO_ENC_MORE
	WEAVE_A
	NEON_IO_ENC_MORE
	WEAVE_B
	X5_DEC_COUNT(enc5_pass2_loop)

	// Iteration 97: scalar block 49 (MSG_LAST) A-phase.
	NEON_IO_ENC_MORE
	SCALAR_IO_ENC_LAST
	WEAVE_A

	// Iteration 98: NEON MSG_LAST for chunks 2,3; scalar block 49 B-phase.
	NEON_IO_ENC_LAST
	WEAVE_B

	X5_EPILOGUE
	RET

// func decryptChunks5ARM64(s *state8, d *duplex, src, dst, tags *byte)
TEXT ·decryptChunks5ARM64(SB), NOSPLIT, $120-40
	X5_PROLOGUE

	X5_COUNT(24)
dec5_pass1_loop:
	NEON_IO_DEC_MORE
	SCALAR_IO_DEC_MORE
	WEAVE_A
	NEON_IO_DEC_MORE
	WEAVE_B
	X5_DEC_COUNT(dec5_pass1_loop)

	NEON_IO_DEC_LAST
	SCALAR_IO_DEC_MORE
	WEAVE_A

	X5_PASS1_EPILOGUE

	NEON_IO_DEC_MORE
	WEAVE_B

	X5_COUNT(23)
dec5_pass2_loop:
	NEON_IO_DEC_MORE
	SCALAR_IO_DEC_MORE
	WEAVE_A
	NEON_IO_DEC_MORE
	WEAVE_B
	X5_DEC_COUNT(dec5_pass2_loop)

	NEON_IO_DEC_MORE
	SCALAR_IO_DEC_LAST
	WEAVE_A

	NEON_IO_DEC_LAST
	WEAVE_B

	X5_EPILOGUE
	RET
