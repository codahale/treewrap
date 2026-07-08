//go:build !arm64 || purego

package tw128

// hasLeafBatch5 reports that this platform has no 5-chunk hybrid kernel; the
// scheduler goes straight to the 8-wide batch and remainder paths.
const hasLeafBatch5 = false

func (g *aggregator) processLeafBatch5(dst, src []byte) {
	panic("tw128: no 5-chunk kernel on this platform")
}
