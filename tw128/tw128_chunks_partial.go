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

func finishChunk0PartialEncrypt(g *aggregator, s *state8, src, dst []byte, tailLen, bodyBlocks int) {
	var trunk, leaf duplex
	extractChunk0PartialState(&trunk, &leaf, s)

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
	extractChunk0PartialState(&trunk, &leaf, s)

	off := bodyBlocks * rhoBytes
	trunk.bodyMore(dst[off:ChunkSize], src[off:ChunkSize], true, msgMore)
	trunk.closeBlock(msgLast)

	tailOff := ChunkSize + off
	leaf.bodyMore(dst[tailOff:ChunkSize+tailLen], src[tailOff:ChunkSize+tailLen], true, msgMore)
	leaf.closeBlock(msgLast)

	finishChunk0Partial(g, &trunk, &leaf)
}

func extractChunk0PartialState(trunk, leaf *duplex, s *state8) {
	for lane := range lanes {
		trunk.a[lane] = s.a[lane][0]
		leaf.a[lane] = s.a[lane][1]
	}
}

func finishChunk0Partial(g *aggregator, trunk, leaf *duplex) {
	g.trunk = *trunk
	tag := leaf.tagBytes()
	g.trunk.absorbMore(tag[:], aggMore)
	g.nLeaves++
}
