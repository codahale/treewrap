//go:build amd64 && !purego

package tw128

import (
	"github.com/codahale/treewrap/tw128/internal/cpuid"
)

//go:noescape
func encryptChunksBodyAVX512N(s *state8, src, dst *byte, n uint64)

//go:noescape
func decryptChunksBodyAVX512N(s *state8, src, dst *byte, n uint64)

//go:noescape
func encryptChunksBodyAVX2N(s *state8, src, dst *byte, n uint64)

//go:noescape
func decryptChunksBodyAVX2N(s *state8, src, dst *byte, n uint64)

func encryptChunksBodyN(s *state8, src, dst []byte, n int) {
	if cpuid.HasAVX512 {
		encryptChunksBodyAVX512N(s, &src[0], &dst[0], uint64(n))
	} else {
		encryptChunksBodyAVX2N(s, &src[0], &dst[0], uint64(n))
	}
}

func decryptChunksBodyN(s *state8, src, dst []byte, n int) {
	if cpuid.HasAVX512 {
		decryptChunksBodyAVX512N(s, &src[0], &dst[0], uint64(n))
	} else {
		decryptChunksBodyAVX2N(s, &src[0], &dst[0], uint64(n))
	}
}

// encryptLeafRemainder encrypts n complete leaf chunks (n in 2..7) at indices
// g.nLeaves+1 .. g.nLeaves+n in one backend pass: register-resident masked
// gather/scatter on AVX-512, dummy-lane x4 on AVX2. It reads the chunks
// directly from src with no scratch buffer, absorbs their leaf tags into the
// trunk aggregation transcript, and advances the leaf counter. src and dst
// must each be exactly n*ChunkSize bytes. It reports whether a kernel ran; on
// amd64 one always does.
func encryptLeafRemainder(g *aggregator, src, dst []byte, n int) bool {
	var s state8
	initLeafBatch8(&s, g.key[:], g.nonce[:], g.nLeaves+1)
	var tags leafTagBuffer
	encryptChunksBodyN(&s, src, dst, n)
	finishEncryptChunkLanes(&s, src, dst, &tags, n)
	g.absorbLeafTags(tags[:n*leafTagSize], n)
	return true
}

// decryptLeafRemainder is the decrypt counterpart of encryptLeafRemainder.
func decryptLeafRemainder(g *aggregator, src, dst []byte, n int) bool {
	var s state8
	initLeafBatch8(&s, g.key[:], g.nonce[:], g.nLeaves+1)
	var tags leafTagBuffer
	decryptChunksBodyN(&s, src, dst, n)
	finishDecryptChunkLanes(&s, src, dst, &tags, n)
	g.absorbLeafTags(tags[:n*leafTagSize], n)
	return true
}
