//go:build !amd64 || purego

package tw128

// encryptLeafRemainder / decryptLeafRemainder report false on platforms without an
// n-chunk remainder kernel, leaving processCompleteLeafChunks to fall back to
// its pair and x1 remainder handling.

func encryptLeafRemainder(_ *aggregator, _, _ []byte, _ int) bool { return false }

func decryptLeafRemainder(_ *aggregator, _, _ []byte, _ int) bool { return false }
