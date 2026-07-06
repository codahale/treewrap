//go:build amd64 && !purego

package tw128

import (
	"github.com/codahale/treewrap/tw128/internal/cpuid"
)

// Lane-0 fusion: the trunk's chunk-0 message phase has the same kernel-visible
// schedule as a leaf chunk — 49 rho-blocks, 48 closed with MSG_MORE and the
// last with MSG_LAST, SpongeWrap absorb in both directions — and differs only
// in its initial duplex state. The chunk kernels are indifferent to initial
// state and hand the full post-close state back through the state8, so chunk 0
// can ride lane 0 of the 8-wide (k == 8) or remainder (k in 2..7) kernels
// alongside leaves 1..k-1, which are contiguous with it in the message.

// encryptChunk0Fused encrypts trunk chunk 0 and the complete leaf chunks
// 1..k-1 (k in 2..8) in a single kernel pass: lane 0 carries the trunk's
// post-init/post-AD state through its chunk-0 message phase while lanes
// 1..k-1 run the leaves. It writes the trunk's post-MSG_LAST state back,
// absorbs the k-1 leaf tags into the aggregation transcript in leaf order,
// and advances the leaf counter. src and dst must be exactly k*ChunkSize
// bytes (chunk 0 first), and g must be at the start of the cascade
// (g.nLeaves == 0, trunk block open at pos 0). It returns the number of
// chunks consumed; on amd64 that is always k.
func encryptChunk0Fused(g *aggregator, src, dst []byte, k int) int {
	// Lanes 1..7 are leaves 1..7. Lane 0's "leaf 0" init is discarded below:
	// chunk ID 0 is never used by the construction (leaf IDs start at 1).
	var s state8
	initChunks(&s, g.key[:], g.nonce[:], 0)
	for lane := range lanes {
		s.a[lane][0] = g.trunk.a[lane]
	}

	var tags [256]byte
	if k == 8 {
		encryptChunksArch(&s, src, dst, &tags)
	} else {
		if cpuid.HasAVX512 {
			encryptChunksBodyAVX512N(&s, &src[0], &dst[0], uint64(k))
		} else {
			encryptChunksBodyAVX2N(&s, &src[0], &dst[0], uint64(k))
		}
		finishEncryptChunksN(&s, src, dst, &tags, k)
	}

	// Lane 0 is now the trunk just after its chunk-0 MSG_LAST close; the fused
	// path never touches trunk.pos, which stays 0 throughout. tags[0:32] is
	// lane 0's keystream prefix, not a leaf tag, and is unused.
	for lane := range lanes {
		g.trunk.a[lane] = s.a[lane][0]
	}
	g.absorbLeafTags(tags[leafTagSize:k*leafTagSize], k-1)
	return k
}

// decryptChunk0Fused is the decrypt counterpart of encryptChunk0Fused.
func decryptChunk0Fused(g *aggregator, src, dst []byte, k int) int {
	var s state8
	initChunks(&s, g.key[:], g.nonce[:], 0)
	for lane := range lanes {
		s.a[lane][0] = g.trunk.a[lane]
	}

	var tags [256]byte
	if k == 8 {
		decryptChunksArch(&s, src, dst, &tags)
	} else {
		if cpuid.HasAVX512 {
			decryptChunksBodyAVX512N(&s, &src[0], &dst[0], uint64(k))
		} else {
			decryptChunksBodyAVX2N(&s, &src[0], &dst[0], uint64(k))
		}
		finishDecryptChunksN(&s, src, dst, &tags, k)
	}

	for lane := range lanes {
		g.trunk.a[lane] = s.a[lane][0]
	}
	g.absorbLeafTags(tags[leafTagSize:k*leafTagSize], k-1)
	return k
}
