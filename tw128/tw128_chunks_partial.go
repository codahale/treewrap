package tw128

func partialBodyBlocks(n int) int {
	return (n+rhoBytes-1)/rhoBytes - 1
}

func initChunk0PartialState(s *state8, g *aggregator, leafIndex uint64) {
	var leaf duplex
	p := leafInit(g.key[:], g.nonce[:], leafIndex)
	leaf.initWith(p[:])

	initPairStateFromDuplexes(s, &g.trunk, &leaf)
}

func initCompleteLeafPartialState(s *state8, g *aggregator) {
	var full, partial duplex
	p := leafInit(g.key[:], g.nonce[:], g.nLeaves+1)
	full.initWith(p[:])
	p = leafInit(g.key[:], g.nonce[:], g.nLeaves+2)
	partial.initWith(p[:])

	initPairStateFromDuplexes(s, &full, &partial)
}

func finishChunk0PartialEncrypt(g *aggregator, s *state8, src, dst []byte, tailLen, bodyBlocks int) {
	var trunk, leaf duplex
	extractPairState(&trunk, &leaf, s)

	off := bodyBlocks * rhoBytes
	trunk.bodyMore(dst[off:ChunkSize], src[off:ChunkSize], false, msgMore)
	trunk.closeBlock(msgLast)

	tailOff := ChunkSize + off
	leaf.bodyMore(dst[tailOff:ChunkSize+tailLen], src[tailOff:ChunkSize+tailLen], false, msgMore)
	leaf.closeBlock(msgLast)

	finishChunk0Partial(g, &trunk, &leaf)
}

func finishChunk0PartialDecrypt(g *aggregator, s *state8, src, dst []byte, tailLen, bodyBlocks int) {
	var trunk, leaf duplex
	extractPairState(&trunk, &leaf, s)

	off := bodyBlocks * rhoBytes
	trunk.bodyMore(dst[off:ChunkSize], src[off:ChunkSize], true, msgMore)
	trunk.closeBlock(msgLast)

	tailOff := ChunkSize + off
	leaf.bodyMore(dst[tailOff:ChunkSize+tailLen], src[tailOff:ChunkSize+tailLen], true, msgMore)
	leaf.closeBlock(msgLast)

	finishChunk0Partial(g, &trunk, &leaf)
}

func finishCompleteLeafPartialEncrypt(g *aggregator, s *state8, src, dst []byte, tailLen, bodyBlocks int) {
	var full, partial duplex
	extractPairState(&full, &partial, s)

	off := bodyBlocks * rhoBytes
	full.bodyMore(dst[off:ChunkSize], src[off:ChunkSize], false, msgMore)
	full.closeBlock(msgLast)

	tailOff := ChunkSize + off
	partial.bodyMore(dst[tailOff:ChunkSize+tailLen], src[tailOff:ChunkSize+tailLen], false, msgMore)
	partial.closeBlock(msgLast)

	finishCompleteLeafPartial(g, &full, &partial)
}

func finishCompleteLeafPartialDecrypt(g *aggregator, s *state8, src, dst []byte, tailLen, bodyBlocks int) {
	var full, partial duplex
	extractPairState(&full, &partial, s)

	off := bodyBlocks * rhoBytes
	full.bodyMore(dst[off:ChunkSize], src[off:ChunkSize], true, msgMore)
	full.closeBlock(msgLast)

	tailOff := ChunkSize + off
	partial.bodyMore(dst[tailOff:ChunkSize+tailLen], src[tailOff:ChunkSize+tailLen], true, msgMore)
	partial.closeBlock(msgLast)

	finishCompleteLeafPartial(g, &full, &partial)
}

func extractPairState(d0, d1 *duplex, s *state8) {
	for lane := range lanes {
		d0.a[lane] = s.a[lane][0]
		d1.a[lane] = s.a[lane][1]
	}
}

func finishChunk0Partial(g *aggregator, trunk, leaf *duplex) {
	g.trunk = *trunk
	tag := leaf.tagBytes()
	g.absorbLeafTags(tag[:], 1)
}

func finishCompleteLeafPartial(g *aggregator, full, partial *duplex) {
	tag := full.tagBytes()
	g.absorbLeafTags(tag[:], 1)
	tag = partial.tagBytes()
	g.absorbLeafTags(tag[:], 1)
}
