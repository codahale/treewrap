//go:build arm64 && !purego

#include "textflag.h"

// func cntvct() uint64
TEXT ·cntvct(SB), NOSPLIT, $0-8
	ISB	$15
	WORD	$0xd53be040 // MRS CNTVCT_EL0, R0
	MOVD	R0, ret+0(FP)
	RET

// func cntfrq() uint64
TEXT ·cntfrq(SB), NOSPLIT, $0-8
	WORD	$0xd53be000 // MRS CNTFRQ_EL0, R0
	MOVD	R0, ret+0(FP)
	RET

// func calibOps(iters uint64) uint64
//
// Executes 64*iters dependent ADDs on R0. A dependent integer-ADD chain is
// latency-bound at 1 cycle/op on every Apple core (M1-M4), so the loop runs in
// ~64*iters CPU cycles. The 64x unroll drowns out the per-iteration loop
// overhead (the independent SUBS/BNE chain on R1). The result is returned to
// stop the compiler/linker from eliding the work.
TEXT ·calibOps(SB), NOSPLIT, $0-16
	MOVD	iters+0(FP), R1
	MOVD	$0, R0
loop:
	ADD	$1, R0, R0
	ADD	$1, R0, R0
	ADD	$1, R0, R0
	ADD	$1, R0, R0
	ADD	$1, R0, R0
	ADD	$1, R0, R0
	ADD	$1, R0, R0
	ADD	$1, R0, R0
	ADD	$1, R0, R0
	ADD	$1, R0, R0
	ADD	$1, R0, R0
	ADD	$1, R0, R0
	ADD	$1, R0, R0
	ADD	$1, R0, R0
	ADD	$1, R0, R0
	ADD	$1, R0, R0
	ADD	$1, R0, R0
	ADD	$1, R0, R0
	ADD	$1, R0, R0
	ADD	$1, R0, R0
	ADD	$1, R0, R0
	ADD	$1, R0, R0
	ADD	$1, R0, R0
	ADD	$1, R0, R0
	ADD	$1, R0, R0
	ADD	$1, R0, R0
	ADD	$1, R0, R0
	ADD	$1, R0, R0
	ADD	$1, R0, R0
	ADD	$1, R0, R0
	ADD	$1, R0, R0
	ADD	$1, R0, R0
	ADD	$1, R0, R0
	ADD	$1, R0, R0
	ADD	$1, R0, R0
	ADD	$1, R0, R0
	ADD	$1, R0, R0
	ADD	$1, R0, R0
	ADD	$1, R0, R0
	ADD	$1, R0, R0
	ADD	$1, R0, R0
	ADD	$1, R0, R0
	ADD	$1, R0, R0
	ADD	$1, R0, R0
	ADD	$1, R0, R0
	ADD	$1, R0, R0
	ADD	$1, R0, R0
	ADD	$1, R0, R0
	ADD	$1, R0, R0
	ADD	$1, R0, R0
	ADD	$1, R0, R0
	ADD	$1, R0, R0
	ADD	$1, R0, R0
	ADD	$1, R0, R0
	ADD	$1, R0, R0
	ADD	$1, R0, R0
	ADD	$1, R0, R0
	ADD	$1, R0, R0
	ADD	$1, R0, R0
	ADD	$1, R0, R0
	ADD	$1, R0, R0
	ADD	$1, R0, R0
	ADD	$1, R0, R0
	ADD	$1, R0, R0
	SUBS	$1, R1, R1
	BNE	loop
	MOVD	R0, ret+8(FP)
	RET
