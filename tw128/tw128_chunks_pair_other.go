//go:build !arm64 || purego

package tw128

// encryptChunkPair / decryptChunkPair report false on platforms without a 2-wide
// chunk kernel, leaving processCompleteLeafChunks to fall back to its
// remainder-kernel and x1 handling.

func encryptChunkPair(_ *aggregator, _, _ []byte) bool { return false }

func decryptChunkPair(_ *aggregator, _, _ []byte) bool { return false }
