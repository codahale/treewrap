//go:build !purego

#include "textflag.h"
#include "permute_arm64.h"

// func p1600x8Lane(a *state8)
TEXT ·p1600x8Lane(SB), NOSPLIT, $0-8
	MOVD	a+0(FP), R0

	// Pair (0,1): offset 0, stride 64 bytes per lane.
	MOVD	R0, R2
	MOVD	$tw128_round_consts(SB), R1
	ADD	$96, R1
	LOAD25_STRIDE(R2, 64)
	KECCAK_12_ROUNDS
	MOVD	R0, R2
	STORE25_STRIDE(R2, 64)

	// Pair (2,3): offset 16, stride 64 bytes per lane.
	ADD	$16, R0, R2
	MOVD	$tw128_round_consts(SB), R1
	ADD	$96, R1
	LOAD25_STRIDE(R2, 64)
	KECCAK_12_ROUNDS
	ADD	$16, R0, R2
	STORE25_STRIDE(R2, 64)

	// Pair (4,5): offset 32, stride 64 bytes per lane.
	ADD	$32, R0, R2
	MOVD	$tw128_round_consts(SB), R1
	ADD	$96, R1
	LOAD25_STRIDE(R2, 64)
	KECCAK_12_ROUNDS
	ADD	$32, R0, R2
	STORE25_STRIDE(R2, 64)

	// Pair (6,7): offset 48, stride 64 bytes per lane.
	ADD	$48, R0, R2
	MOVD	$tw128_round_consts(SB), R1
	ADD	$96, R1
	LOAD25_STRIDE(R2, 64)
	KECCAK_12_ROUNDS
	ADD	$48, R0, R2
	STORE25_STRIDE(R2, 64)

	RET

// func p1600x6Lane(a *state8)
//
// Permutes instance pairs (0,1), (2,3), and (4,5) only. The 5-chunk hybrid
// batch initializes five leaf lanes (four NEON plus the harvested scalar
// lane), so the fourth pair's permute would be entirely wasted; instances 6
// and 7 are left untouched and unread.
TEXT ·p1600x6Lane(SB), NOSPLIT, $0-8
	MOVD	a+0(FP), R0

	// Pair (0,1): offset 0, stride 64 bytes per lane.
	MOVD	R0, R2
	MOVD	$tw128_round_consts(SB), R1
	ADD	$96, R1
	LOAD25_STRIDE(R2, 64)
	KECCAK_12_ROUNDS
	MOVD	R0, R2
	STORE25_STRIDE(R2, 64)

	// Pair (2,3): offset 16, stride 64 bytes per lane.
	ADD	$16, R0, R2
	MOVD	$tw128_round_consts(SB), R1
	ADD	$96, R1
	LOAD25_STRIDE(R2, 64)
	KECCAK_12_ROUNDS
	ADD	$16, R0, R2
	STORE25_STRIDE(R2, 64)

	// Pair (4,5): offset 32, stride 64 bytes per lane.
	ADD	$32, R0, R2
	MOVD	$tw128_round_consts(SB), R1
	ADD	$96, R1
	LOAD25_STRIDE(R2, 64)
	KECCAK_12_ROUNDS
	ADD	$32, R0, R2
	STORE25_STRIDE(R2, 64)

	RET
