//go:build !arm64 || purego

package tw128

// bodyBlocksArch reports that this platform has no in-register x1 body
// kernel; the caller's bodyMore handles the whole body.
func (d *duplex) bodyBlocksArch(dst, src []byte, decrypt bool) int {
	return 0
}
