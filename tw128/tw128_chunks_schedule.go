package tw128

// processChunkedMessage handles messages too large for the trunk-only path. It
// processes chunk 0, complete leaf chunks, and an optional final ragged leaf,
// absorbing leaf tags into the trunk in transcript order.
func (g *aggregator) processChunkedMessage(dst, src []byte) {
	if g.tryFuseChunk0PartialLeaf(dst, src) {
		return
	}

	consumed := g.processChunk0AndCompleteLeaves(dst, src)
	src, dst = src[consumed*ChunkSize:], dst[consumed*ChunkSize:]

	if n := len(src) / ChunkSize; n > 0 {
		g.processCompleteLeafChunks(dst[:n*ChunkSize], src[:n*ChunkSize], n)
		src, dst = src[n*ChunkSize:], dst[n*ChunkSize:]
	}

	if len(src) > 0 {
		g.processLeafSerial(dst, src)
	}
}

// tryFuseChunk0PartialLeaf handles the first boundary case after the trunk-only
// path: chunk 0 plus one ragged leaf. On platforms with a suitable pair kernel
// it processes their shared full MSG_MORE blocks together, then finishes their
// different final blocks separately.
func (g *aggregator) tryFuseChunk0PartialLeaf(dst, src []byte) bool {
	if len(src) >= 2*ChunkSize {
		return false
	}
	tailLen := len(src) - ChunkSize
	if g.decrypt {
		return decryptChunk0PartialFused(g, src, dst, tailLen)
	}
	return encryptChunk0PartialFused(g, src, dst, tailLen)
}

// processChunk0AndCompleteLeaves handles chunk 0 and any immediately following
// complete leaves that can be fused into the first backend call. It returns the
// number of chunks consumed from src/dst.
func (g *aggregator) processChunk0AndCompleteLeaves(dst, src []byte) int {
	if nComplete := (len(src) - ChunkSize) / ChunkSize; nComplete >= 1 {
		k := min(1+nComplete, 8)
		if consumed := g.tryFuseChunk0CompleteLeaves(dst[:k*ChunkSize], src[:k*ChunkSize], k); consumed != 0 {
			return consumed
		}
	}

	g.processChunk0InTrunk(dst[:ChunkSize], src[:ChunkSize])
	return 1
}

func (g *aggregator) tryFuseChunk0CompleteLeaves(dst, src []byte, k int) int {
	if g.decrypt {
		return decryptChunk0Fused(g, src, dst, k)
	}
	return encryptChunk0Fused(g, src, dst, k)
}

func (g *aggregator) processChunk0InTrunk(dst, src []byte) {
	g.trunk.bodyMore(dst, src, g.decrypt, msgMore)
	g.trunk.closeBlock(msgLast)
}

// processCompleteLeafChunks processes nFlush complete leaf chunks via the SIMD
// cascade, absorbing their tags into the trunk in leaf order.
func (g *aggregator) processCompleteLeafChunks(dst, src []byte, nFlush int) {
	idx := 0

	for idx+8 <= nFlush {
		off := idx * ChunkSize
		g.processLeafBatch8(dst[off:off+8*ChunkSize], src[off:off+8*ChunkSize])
		idx += 8
	}

	// 2-wide pass: drain complete chunks in pairs where a 2-wide kernel is
	// available (arm64). Platforms without one report false and fall through to
	// the n-wide remainder kernel or x1 fallback.
	for idx+2 <= nFlush {
		off := idx * ChunkSize
		if !g.tryProcessLeafPair(dst[off:off+2*ChunkSize], src[off:off+2*ChunkSize]) {
			break
		}
		idx += 2
	}

	// Remainder pass: drain a 2..7 chunk remainder with a single backend call
	// where available. On amd64 this is the AVX-512/AVX2 n-wide path; on arm64
	// the pair pass has already left fewer than two chunks.
	if rem := nFlush - idx; rem >= 2 {
		off := idx * ChunkSize
		if g.tryProcessLeafRemainder(dst[off:off+rem*ChunkSize], src[off:off+rem*ChunkSize], rem) {
			idx += rem
		}
	}

	for idx < nFlush {
		off := idx * ChunkSize
		g.processLeafSerial(dst[off:off+ChunkSize], src[off:off+ChunkSize])
		idx++
	}
}

func (g *aggregator) processLeafBatch8(dst, src []byte) {
	var tags [256]byte
	if g.decrypt {
		decryptChunks(g.key[:], g.nonce[:], g.nLeaves+1, src, dst, &tags)
	} else {
		encryptChunks(g.key[:], g.nonce[:], g.nLeaves+1, src, dst, &tags)
	}
	g.trunk.absorbMore(tags[:], aggMore)
	g.nLeaves += 8
}

func (g *aggregator) tryProcessLeafPair(dst, src []byte) bool {
	if g.decrypt {
		return decryptChunkPair(g, src, dst)
	}
	return encryptChunkPair(g, src, dst)
}

func (g *aggregator) tryProcessLeafRemainder(dst, src []byte, n int) bool {
	if g.decrypt {
		return decryptChunkRun(g, src, dst, n)
	}
	return encryptChunkRun(g, src, dst, n)
}

func (g *aggregator) processLeafSerial(dst, src []byte) {
	var leaf duplex
	if g.decrypt {
		decryptX1(g.key[:], g.nonce[:], g.nLeaves+1, src, dst, &leaf)
	} else {
		encryptX1(g.key[:], g.nonce[:], g.nLeaves+1, src, dst, &leaf)
	}
	tag := leaf.tagBytes()
	g.trunk.absorbMore(tag[:], aggMore)
	g.nLeaves++
}
