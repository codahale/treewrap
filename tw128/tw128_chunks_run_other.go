//go:build !amd64 || purego

package tw128

// encryptChunkRun / decryptChunkRun report false on platforms without an
// n-chunk remainder kernel, leaving processCompleteLeafChunks to fall back to
// its pair and x1 remainder handling.

func encryptChunkRun(_ *aggregator, _, _ []byte, _ int) bool { return false }

func decryptChunkRun(_ *aggregator, _, _ []byte, _ int) bool { return false }
