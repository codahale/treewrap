//go:build !arm64 || purego

package tw128

func canFuseCompleteLeafWithPartialLeaf(_ int) bool { return false }

func encryptChunk0PartialFused(_ *aggregator, _, _ []byte, _ int) bool { return false }

func decryptChunk0PartialFused(_ *aggregator, _, _ []byte, _ int) bool { return false }

func encryptCompleteLeafPartialFused(_ *aggregator, _, _ []byte, _ int) bool { return false }

func decryptCompleteLeafPartialFused(_ *aggregator, _, _ []byte, _ int) bool { return false }
