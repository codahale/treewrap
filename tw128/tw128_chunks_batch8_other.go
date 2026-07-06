//go:build (!amd64 && !arm64) || purego

package tw128

func encryptLeafBatch8Arch(_ *state8, _, _ []byte, _ *[256]byte) bool { return false }

func decryptLeafBatch8Arch(_ *state8, _, _ []byte, _ *[256]byte) bool { return false }
