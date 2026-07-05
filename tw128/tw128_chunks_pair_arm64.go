//go:build arm64 && !purego

package tw128

//go:noescape
func encryptChunksPairARM64(s *state8, src0, src1, dst0, dst1, tags *byte)

//go:noescape
func decryptChunksPairARM64(s *state8, src0, src1, dst0, dst1, tags *byte)

//go:noescape
func encryptChunkPairBodyARM64(s *state8, src0, src1, dst0, dst1 *byte, blocks uint64)

//go:noescape
func decryptChunkPairBodyARM64(s *state8, src0, src1, dst0, dst1 *byte, blocks uint64)

// initChunkPairState initializes instances 0 and 1 of s with INIT_LAST for two
// consecutive leaf indices, leaving each leaf's first keystream block in its
// rate. It reuses the x1 init permute (one per leaf) and transposes the two
// states into s's lane-major layout; instances 2..7 are left zero and unread.
func initChunkPairState(s *state8, key, nonce []byte, baseIndex uint64) {
	var d0, d1 duplex
	p0 := leafInit(key, nonce, baseIndex)
	d0.initWith(p0[:])
	p1 := leafInit(key, nonce, baseIndex+1)
	d1.initWith(p1[:])
	initPairStateFromDuplexes(s, &d0, &d1)
}

// encryptChunkPair encrypts the two complete leaf chunks at indices g.nLeaves+1
// and g.nLeaves+2 in a single 2-wide NEON pass, absorbs their leaf tags into the
// trunk aggregation transcript, and advances the leaf counter. src and dst must
// each be exactly 2*ChunkSize bytes. It reports whether a 2-wide kernel ran.
func encryptChunkPair(g *aggregator, src, dst []byte) bool {
	var s state8
	initChunkPairState(&s, g.key[:], g.nonce[:], g.nLeaves+1)
	var tags [256]byte
	encryptChunksPairARM64(&s, &src[0], &src[ChunkSize], &dst[0], &dst[ChunkSize], &tags[0])
	g.trunk.absorbMore(tags[:2*leafTagSize], aggMore)
	g.nLeaves += 2
	return true
}

// decryptChunkPair is the decrypt counterpart of encryptChunkPair.
func decryptChunkPair(g *aggregator, src, dst []byte) bool {
	var s state8
	initChunkPairState(&s, g.key[:], g.nonce[:], g.nLeaves+1)
	var tags [256]byte
	decryptChunksPairARM64(&s, &src[0], &src[ChunkSize], &dst[0], &dst[ChunkSize], &tags[0])
	g.trunk.absorbMore(tags[:2*leafTagSize], aggMore)
	g.nLeaves += 2
	return true
}
