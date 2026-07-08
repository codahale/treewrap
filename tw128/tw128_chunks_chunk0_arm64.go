//go:build arm64 && !purego

package tw128

// Lane-0 fusion on arm64: the NEON kernels store pair (0,1)'s permutation
// state back into the state8, so the trunk's chunk-0 phase can ride instance
// 0. With seven or more complete leaves the full x8 kernel carries the trunk
// alongside leaves 1..7; below that the 2-wide pair kernel carries it
// alongside leaf 1 alone, and the remaining leaves take the normal cascade.

// encryptChunk0Fused encrypts trunk chunk 0 fused with the leading complete
// leaf chunks: lane 0 carries the trunk's post-init/post-AD state through its
// chunk-0 message phase while the other active lanes run leaves. It writes
// the trunk's post-MSG_LAST state back, absorbs the leaf tags it produced in
// leaf order, advances the leaf counter, and returns the number of chunks
// consumed: 8 (x8 kernel) when k == 8, otherwise 2 (pair kernel). src and dst
// must be at least that many chunks (chunk 0 first), and g must be at the
// start of the cascade (g.nLeaves == 0, trunk block open at pos 0).
func encryptChunk0Fused(g *aggregator, src, dst []byte, k int) int {
	var s state8
	var tags leafTagBuffer

	if k == 8 {
		initChunk0BatchState(&s, g)
		encryptChunksARM64(&s, &src[0], &dst[0], &tags[0])
		finishChunk0Lanes(g, &s, tags[:], 8)
		return 8
	}

	// 2-wide: the trunk in instance 0, leaf 1 in instance 1.
	initChunk0PairState(&s, g, 1)
	encryptChunksPairARM64(&s, &src[0], &src[ChunkSize], &dst[0], &dst[ChunkSize], &tags[0])
	finishChunk0Lanes(g, &s, tags[:], 2)
	return 2
}

// decryptChunk0Fused is the decrypt counterpart of encryptChunk0Fused.
func decryptChunk0Fused(g *aggregator, src, dst []byte, k int) int {
	var s state8
	var tags leafTagBuffer

	if k == 8 {
		initChunk0BatchState(&s, g)
		decryptChunksARM64(&s, &src[0], &dst[0], &tags[0])
		finishChunk0Lanes(g, &s, tags[:], 8)
		return 8
	}

	initChunk0PairState(&s, g, 1)
	decryptChunksPairARM64(&s, &src[0], &src[ChunkSize], &dst[0], &dst[ChunkSize], &tags[0])
	finishChunk0Lanes(g, &s, tags[:], 2)
	return 2
}

// initChunk0PairState initializes instance 0 with the trunk and instance 1
// with the requested leaf. It is used by pair-width chunk0 fusion paths.
func initChunk0PairState(s *state8, g *aggregator, leafIndex uint64) {
	var leaf duplex
	p := leafInit(g.key[:], g.nonce[:], leafIndex)
	leaf.initWith(p[:])
	initPairStateFromDuplexes(s, &g.trunk, &leaf)
}
