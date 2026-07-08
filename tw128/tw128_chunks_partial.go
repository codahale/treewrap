package tw128

func partialBodyBlocks(n int) int {
	return (n+rhoBytes-1)/rhoBytes - 1
}

func initChunk0PartialState(s *state8, g *aggregator, leafIndex uint64) {
	initChunk0PairState(s, g, leafIndex)
}

func initCompleteLeafPartialState(s *state8, g *aggregator) {
	var full, partial duplex
	p := leafInit(g.key[:], g.nonce[:], g.nLeaves+1)
	full.initWith(p[:])
	p = leafInit(g.key[:], g.nonce[:], g.nLeaves+2)
	partial.initWith(p[:])

	initPairStateFromDuplexes(s, &full, &partial)
}

func finishChunk0PartialFused(g *aggregator, s *state8, src, dst []byte, tailLen, bodyBlocks int, decrypt bool) {
	var trunk, leaf duplex
	extractPairState(&trunk, &leaf, s)

	finishPartialBodies(&trunk, &leaf, src, dst, tailLen, bodyBlocks, decrypt)
	absorbChunk0Partial(g, &trunk, &leaf)
}

func finishCompleteLeafPartialFused(g *aggregator, s *state8, src, dst []byte, tailLen, bodyBlocks int, decrypt bool) {
	var full, partial duplex
	extractPairState(&full, &partial, s)

	finishPartialBodies(&full, &partial, src, dst, tailLen, bodyBlocks, decrypt)
	absorbCompleteLeafPartial(g, &full, &partial)
}

func finishPartialBodies(d0, d1 *duplex, src, dst []byte, tailLen, bodyBlocks int, decrypt bool) {
	// The complete chunk in d0 may have many full blocks left when the fused
	// pass was short (a small ragged tail); drain them in-register first.
	off := bodyBlocks * rhoBytes
	consumed := off + d0.bodyBlocksArch(dst[off:ChunkSize], src[off:ChunkSize], decrypt)
	d0.bodyMore(dst[consumed:ChunkSize], src[consumed:ChunkSize], decrypt, msgMore)
	d0.closeBlock(msgLast)

	tailOff := ChunkSize + off
	d1.bodyMore(dst[tailOff:ChunkSize+tailLen], src[tailOff:ChunkSize+tailLen], decrypt, msgMore)
	d1.closeBlock(msgLast)
}

func extractPairState(d0, d1 *duplex, s *state8) {
	for lane := range lanes {
		d0.a[lane] = s.a[lane][0]
		d1.a[lane] = s.a[lane][1]
	}
}

func absorbChunk0Partial(g *aggregator, trunk, leaf *duplex) {
	g.trunk = *trunk
	tag := leaf.tagBytes()
	g.absorbLeafTags(tag[:], 1)
}

func absorbCompleteLeafPartial(g *aggregator, full, partial *duplex) {
	tag := full.tagBytes()
	g.absorbLeafTags(tag[:], 1)
	tag = partial.tagBytes()
	g.absorbLeafTags(tag[:], 1)
}
