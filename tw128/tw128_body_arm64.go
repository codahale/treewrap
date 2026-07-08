//go:build arm64 && !purego

package tw128

//go:noescape
func encryptBodyBlocksARM64(d *duplex, src, dst *byte, blocks uint64)

//go:noescape
func decryptBodyBlocksARM64(d *duplex, src, dst *byte, blocks uint64)

// bodyBlocksArch processes the full MSG_MORE-closed rho-blocks of a body
// (those followed by at least one more sigma byte) with the state held in
// registers across all blocks, and returns the number of bytes consumed.
// The caller finishes the remaining 1..rhoBytes with bodyMore and the
// MSG_LAST close. d.pos must be 0.
func (d *duplex) bodyBlocksArch(dst, src []byte, decrypt bool) int {
	n := (len(src) - 1) / rhoBytes
	if n < 1 {
		return 0
	}
	if decrypt {
		decryptBodyBlocksARM64(d, &src[0], &dst[0], uint64(n))
	} else {
		encryptBodyBlocksARM64(d, &src[0], &dst[0], uint64(n))
	}
	return n * rhoBytes
}
