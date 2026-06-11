//go:build !amd64 || purego

package tw128

// encryptChunk0Fused / decryptChunk0Fused report false on platforms without a
// lane-0 fused path, leaving crypt to run trunk chunk 0 serially. On arm64 the
// NEON chunk kernels extract leaf tags in assembly without storing the
// permutation state back to the state8, so lane 0's post-close trunk state
// would be lost; a writeback kernel variant is a possible follow-up.

func encryptChunk0Fused(_ *aggregator, _, _ []byte, _ int) bool { return false }

func decryptChunk0Fused(_ *aggregator, _, _ []byte, _ int) bool { return false }
