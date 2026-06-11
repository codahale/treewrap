//go:build (!amd64 && !arm64) || purego

package tw128

// encryptChunk0Fused / decryptChunk0Fused report zero chunks consumed on
// platforms without a lane-0 fused path, leaving crypt to run trunk chunk 0
// serially.

func encryptChunk0Fused(_ *aggregator, _, _ []byte, _ int) int { return 0 }

func decryptChunk0Fused(_ *aggregator, _, _ []byte, _ int) int { return 0 }
