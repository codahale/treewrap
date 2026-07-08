//go:build amd64 && !purego

package tw128

import "github.com/codahale/treewrap/tw128/internal/cpuid"

//go:noescape
func encryptBodyBlocksAVX512(d *duplex, src, dst *byte, blocks uint64)

//go:noescape
func decryptBodyBlocksAVX512(d *duplex, src, dst *byte, blocks uint64)

// bodyBlocksArch processes the full MSG_MORE-closed rho-blocks of a body
// (those followed by at least one more sigma byte) with the state held in
// registers across all blocks, and returns the number of bytes consumed.
// The caller finishes the remaining 1..rhoBytes with bodyMore and the
// MSG_LAST close. d.pos must be 0. Without AVX-512 it reports zero bytes
// consumed and the caller's bodyMore handles the whole body.
func (d *duplex) bodyBlocksArch(dst, src []byte, decrypt bool) int {
	if !cpuid.HasAVX512 {
		return 0
	}
	n := (len(src) - 1) / rhoBytes
	if n < 1 {
		return 0
	}
	if decrypt {
		decryptBodyBlocksAVX512(d, &src[0], &dst[0], uint64(n))
	} else {
		encryptBodyBlocksAVX512(d, &src[0], &dst[0], uint64(n))
	}
	return n * rhoBytes
}
