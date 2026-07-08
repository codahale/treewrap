package tw128

// initChunk0BatchState initializes an x8/n-wide chunk state for lane-0 fusion.
// Lanes 1..7 are leaves 1..7; lane 0's leaf-0 init is overwritten with the
// trunk state because chunk ID 0 is never a real leaf.
func initChunk0BatchState(s *state8, g *aggregator) {
	initLeafBatch8(s, g.key[:], g.nonce[:], 0)
	for lane := range lanes {
		s.a[lane][0] = g.trunk.a[lane]
	}
}

// finishChunk0Lanes writes fused lane 0 back into the trunk and absorbs the
// produced leaf tags. tags[0:leafTagSize] belongs to the trunk lane and is not
// a leaf tag.
func finishChunk0Lanes(g *aggregator, s *state8, tags []byte, consumed int) {
	for lane := range lanes {
		g.trunk.a[lane] = s.a[lane][0]
	}
	g.absorbLeafTags(tags[leafTagSize:consumed*leafTagSize], consumed-1)
}
