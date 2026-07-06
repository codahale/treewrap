//go:build arm64 && !purego

package tw128

func canFuseCompleteLeafWithPartialLeaf(tailLen int) bool {
	return partialBodyBlocks(tailLen) != 0
}

func encryptChunk0PartialFused(g *aggregator, src, dst []byte, tailLen int) bool {
	bodyBlocks := partialBodyBlocks(tailLen)
	if bodyBlocks == 0 {
		return false
	}

	var s state8
	initChunk0PartialState(&s, g, 1)
	encryptChunkPairBodyARM64(&s, &src[0], &src[ChunkSize], &dst[0], &dst[ChunkSize], uint64(bodyBlocks))

	finishChunk0PartialFused(g, &s, src, dst, tailLen, bodyBlocks, false)
	return true
}

func decryptChunk0PartialFused(g *aggregator, src, dst []byte, tailLen int) bool {
	bodyBlocks := partialBodyBlocks(tailLen)
	if bodyBlocks == 0 {
		return false
	}

	var s state8
	initChunk0PartialState(&s, g, 1)
	decryptChunkPairBodyARM64(&s, &src[0], &src[ChunkSize], &dst[0], &dst[ChunkSize], uint64(bodyBlocks))

	finishChunk0PartialFused(g, &s, src, dst, tailLen, bodyBlocks, true)
	return true
}

func encryptCompleteLeafPartialFused(g *aggregator, src, dst []byte, tailLen int) bool {
	bodyBlocks := partialBodyBlocks(tailLen)
	if bodyBlocks == 0 {
		return false
	}

	var s state8
	initCompleteLeafPartialState(&s, g)
	encryptChunkPairBodyARM64(&s, &src[0], &src[ChunkSize], &dst[0], &dst[ChunkSize], uint64(bodyBlocks))

	finishCompleteLeafPartialFused(g, &s, src, dst, tailLen, bodyBlocks, false)
	return true
}

func decryptCompleteLeafPartialFused(g *aggregator, src, dst []byte, tailLen int) bool {
	bodyBlocks := partialBodyBlocks(tailLen)
	if bodyBlocks == 0 {
		return false
	}

	var s state8
	initCompleteLeafPartialState(&s, g)
	decryptChunkPairBodyARM64(&s, &src[0], &src[ChunkSize], &dst[0], &dst[ChunkSize], uint64(bodyBlocks))

	finishCompleteLeafPartialFused(g, &s, src, dst, tailLen, bodyBlocks, true)
	return true
}
