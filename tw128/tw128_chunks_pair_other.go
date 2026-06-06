//go:build !arm64 || purego

package tw128

// encryptChunkPair / decryptChunkPair report false on platforms without a 2-wide
// chunk kernel, leaving processComplete to fall back to its padded-x8 and x1
// remainder handling.

func encryptChunkPair(_ *cryptor, _, _ []byte) bool { return false }

func decryptChunkPair(_ *cryptor, _, _ []byte) bool { return false }
