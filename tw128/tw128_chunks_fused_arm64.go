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
	var tags [256]byte

	if k == 8 {
		// Lanes 1..7 are leaves 1..7. Lane 0's "leaf 0" init is discarded
		// below: chunk ID 0 is never used by the construction (leaf IDs
		// start at 1).
		initChunks(&s, g.key[:], g.nonce[:], 0)
		for lane := range lanes {
			s.a[lane][0] = g.trunk.a[lane]
		}
		encryptChunksARM64(&s, &src[0], &dst[0], &tags[0])
		// Instance 0 is now the trunk just after its chunk-0 MSG_LAST close;
		// the fused path never touches trunk.pos, which stays 0 throughout.
		// tags[0:32] is instance 0's keystream prefix, not a leaf tag, and is
		// unused.
		for lane := range lanes {
			g.trunk.a[lane] = s.a[lane][0]
		}
		g.trunk.absorbMore(tags[leafTagSize:8*leafTagSize], aggMore)
		g.nLeaves += 7
		return 8
	}

	// 2-wide: the trunk in instance 0, leaf 1 in instance 1.
	var d1 duplex
	p := leafInit(g.key[:], g.nonce[:], 1)
	d1.initWith(p[:])
	for lane := range lanes {
		s.a[lane][0] = g.trunk.a[lane]
		s.a[lane][1] = d1.a[lane]
	}
	encryptChunksPairARM64(&s, &src[0], &src[ChunkSize], &dst[0], &dst[ChunkSize], &tags[0])
	for lane := range lanes {
		g.trunk.a[lane] = s.a[lane][0]
	}
	g.trunk.absorbMore(tags[leafTagSize:2*leafTagSize], aggMore)
	g.nLeaves++
	return 2
}

// decryptChunk0Fused is the decrypt counterpart of encryptChunk0Fused.
func decryptChunk0Fused(g *aggregator, src, dst []byte, k int) int {
	var s state8
	var tags [256]byte

	if k == 8 {
		initChunks(&s, g.key[:], g.nonce[:], 0)
		for lane := range lanes {
			s.a[lane][0] = g.trunk.a[lane]
		}
		decryptChunksARM64(&s, &src[0], &dst[0], &tags[0])
		for lane := range lanes {
			g.trunk.a[lane] = s.a[lane][0]
		}
		g.trunk.absorbMore(tags[leafTagSize:8*leafTagSize], aggMore)
		g.nLeaves += 7
		return 8
	}

	var d1 duplex
	p := leafInit(g.key[:], g.nonce[:], 1)
	d1.initWith(p[:])
	for lane := range lanes {
		s.a[lane][0] = g.trunk.a[lane]
		s.a[lane][1] = d1.a[lane]
	}
	decryptChunksPairARM64(&s, &src[0], &src[ChunkSize], &dst[0], &dst[ChunkSize], &tags[0])
	for lane := range lanes {
		g.trunk.a[lane] = s.a[lane][0]
	}
	g.trunk.absorbMore(tags[leafTagSize:2*leafTagSize], aggMore)
	g.nLeaves++
	return 2
}
