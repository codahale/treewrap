//go:build amd64 && !purego

package tw128

import (
	"bytes"
	"fmt"
	"testing"
)

// trunkAfterInit returns a trunk duplex after root init and the optional
// associated-data phase, mirroring crypt's setup.
func trunkAfterInit(key, nonce, ad []byte) (d duplex) {
	p := rootInit(key, nonce)
	d.initWith(p[:])
	if len(ad) > 0 {
		d.absorbMore(ad, adMore)
		d.closeBlock(adLast)
	}
	return d
}

// TestChunk0Fused cross-checks the lane-0 fused path against the serial
// reference built from the same primitives crypt's fallback uses — trunk
// bodyMore/closeBlock over chunk 0, then per-leaf x1 passes with their tags
// absorbed in leaf order — for every fused width k=2..8, both directions, and
// empty and non-empty associated data. Ciphertext, trunk state, and leaf
// count must agree exactly.
func TestChunk0Fused(t *testing.T) {
	key := seq(KeySize)
	nonce := testChunkNonce()

	for _, decrypt := range []bool{false, true} {
		for _, ad := range [][]byte{nil, []byte("fused ad")} {
			for k := 2; k <= 8; k++ {
				name := fmt.Sprintf("decrypt=%v/ad=%d/k=%d", decrypt, len(ad), k)
				t.Run(name, func(t *testing.T) {
					src := make([]byte, k*ChunkSize)
					for i := range src {
						src[i] = byte(i*5 + i>>9 + k)
					}

					// Serial reference.
					refTrunk := trunkAfterInit(key, nonce, ad)
					refDst := make([]byte, len(src))
					refTrunk.bodyMore(refDst[:ChunkSize], src[:ChunkSize], decrypt, msgMore)
					refTrunk.closeBlock(msgLast)
					var leaf duplex
					for i := 1; i < k; i++ {
						off := i * ChunkSize
						if decrypt {
							decryptX1(key, nonce, uint64(i), src[off:off+ChunkSize], refDst[off:off+ChunkSize], &leaf)
						} else {
							encryptX1(key, nonce, uint64(i), src[off:off+ChunkSize], refDst[off:off+ChunkSize], &leaf)
						}
						tag := leaf.tagBytes()
						refTrunk.absorbMore(tag[:], aggMore)
					}

					// Fused path.
					var g aggregator
					copy(g.key[:], key)
					copy(g.nonce[:], nonce)
					g.decrypt = decrypt
					g.trunk = trunkAfterInit(key, nonce, ad)
					dst := make([]byte, len(src))
					var ok bool
					if decrypt {
						ok = decryptChunk0Fused(&g, src, dst, k)
					} else {
						ok = encryptChunk0Fused(&g, src, dst, k)
					}
					if !ok {
						t.Fatal("fused kernel did not run")
					}

					if !bytes.Equal(dst, refDst) {
						t.Errorf("output mismatch at byte %d", firstMismatch(dst, refDst))
					}
					if g.trunk.a != refTrunk.a {
						t.Error("trunk state mismatch")
					}
					if g.trunk.pos != refTrunk.pos {
						t.Errorf("trunk pos mismatch: got %d, want %d", g.trunk.pos, refTrunk.pos)
					}
					if g.nLeaves != uint64(k-1) {
						t.Errorf("leaf count: got %d, want %d", g.nLeaves, k-1)
					}
				})
			}
		}
	}
}
