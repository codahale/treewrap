//go:build !amd64 || purego

package tw128

// encryptChunkRun / decryptChunkRun report false on platforms without a
// register-resident AVX-512 remainder kernel, leaving processComplete to fall
// back to its pair, padded-x8, and x1 remainder handling.

func encryptChunkRun(_ *cryptor, _, _ []byte, _ int) bool { return false }

func decryptChunkRun(_ *cryptor, _, _ []byte, _ int) bool { return false }
