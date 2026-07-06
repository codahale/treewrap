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

// finishEncryptChunksN completes an n-wide chunk encryption after the n-wide
// body kernel has run the chunkBodyBlocks MSG_MORE rho-blocks:
// it encrypts the final chunkLastLen-byte block for instances 0..n-1, closes it
// with MSG_LAST, and extracts the n leaf tags. src and dst hold exactly n
// chunks; closeBlock permutes all eight instances (n..7 are unused and ignored).
func finishEncryptChunksN(s *state8, src, dst []byte, tags *[256]byte, n int) {
	off := chunkBodyBlocks * rhoBytes
	for inst := range n {
		base := inst*ChunkSize + off
		s.encryptBlock(inst, src[base:base+chunkLastLen], dst[base:base+chunkLastLen])
	}
	s.pos = chunkLastLen
	s.closeBlock(msgLast)
	extractChunkTagsN(s, tags, n)
}

// finishDecryptChunksN is the decrypt counterpart of finishEncryptChunksN.
func finishDecryptChunksN(s *state8, src, dst []byte, tags *[256]byte, n int) {
	off := chunkBodyBlocks * rhoBytes
	for inst := range n {
		base := inst*ChunkSize + off
		s.decryptBlock(inst, src[base:base+chunkLastLen], dst[base:base+chunkLastLen])
	}
	s.pos = chunkLastLen
	s.closeBlock(msgLast)
	extractChunkTagsN(s, tags, n)
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
	initChunks(&s, g.key[:], g.nonce[:], g.nLeaves+1)
	var tags [256]byte
	if cpuid.HasAVX512 {
		encryptChunksBodyAVX512N(&s, &src[0], &dst[0], uint64(n))
	} else {
		encryptChunksBodyAVX2N(&s, &src[0], &dst[0], uint64(n))
	}
	finishEncryptChunksN(&s, src, dst, &tags, n)
	g.absorbLeafTags(tags[:n*leafTagSize], n)
	return true
}

// decryptLeafRemainder is the decrypt counterpart of encryptLeafRemainder.
func decryptLeafRemainder(g *aggregator, src, dst []byte, n int) bool {
	var s state8
	initChunks(&s, g.key[:], g.nonce[:], g.nLeaves+1)
	var tags [256]byte
	if cpuid.HasAVX512 {
		decryptChunksBodyAVX512N(&s, &src[0], &dst[0], uint64(n))
	} else {
		decryptChunksBodyAVX2N(&s, &src[0], &dst[0], uint64(n))
	}
	finishDecryptChunksN(&s, src, dst, &tags, n)
	g.absorbLeafTags(tags[:n*leafTagSize], n)
	return true
}
