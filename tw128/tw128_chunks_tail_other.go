//go:build !amd64 || purego

package tw128

// hasWholeMessageTailFusion reports that this platform has no flat-cost
// n-wide kernel worth folding a ragged tail into; tails go through the pair
// fusion or serial paths instead.
const hasWholeMessageTailFusion = false

func canFuseTailBatch(nFull, tailLen int) bool { return false }

func (g *aggregator) tryFuseWholeMessageWithTail(dst, src []byte, nComplete, tailLen int) bool {
	panic("tw128: no whole-message tail fusion on this platform")
}

func (g *aggregator) fuseLeafRemainderWithTail(dst, src []byte, nComplete, tailLen int) {
	panic("tw128: no tail-batch fusion on this platform")
}
