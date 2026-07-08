//go:build !amd64 || purego

package tw128

// hasWholeMessageTailFusion reports that this platform has no flat-cost
// n-wide kernel worth folding a ragged tail into; tails go through the pair
// fusion or serial paths instead.
const hasWholeMessageTailFusion = false

func (g *aggregator) tryFuseWholeMessageWithTail(dst, src []byte, nComplete, tailLen int) bool {
	panic("tw128: no whole-message tail fusion on this platform")
}
