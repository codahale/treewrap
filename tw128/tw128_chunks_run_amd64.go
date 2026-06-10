//go:build amd64 && !purego

package tw128

import (
	"encoding/binary"

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

// finishEncryptChunksN completes an n-wide chunk encryption after the register-
// resident AVX-512 body kernel has run the chunkBodyBlocks MSG_MORE rho-blocks:
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
	for inst := range n {
		binary.LittleEndian.PutUint64(tags[inst*32:], s.a[0][inst])
		binary.LittleEndian.PutUint64(tags[inst*32+8:], s.a[1][inst])
		binary.LittleEndian.PutUint64(tags[inst*32+16:], s.a[2][inst])
		binary.LittleEndian.PutUint64(tags[inst*32+24:], s.a[3][inst])
	}
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
	for inst := range n {
		binary.LittleEndian.PutUint64(tags[inst*32:], s.a[0][inst])
		binary.LittleEndian.PutUint64(tags[inst*32+8:], s.a[1][inst])
		binary.LittleEndian.PutUint64(tags[inst*32+16:], s.a[2][inst])
		binary.LittleEndian.PutUint64(tags[inst*32+24:], s.a[3][inst])
	}
}

// encryptChunkRun encrypts n complete leaf chunks (n in 2..7) at indices
// c.nLeaves+1 .. c.nLeaves+n in a single pass — register-resident masked
// gather/scatter on AVX-512, dummy-lane x4 on AVX2 — reading the chunks
// directly from src with no scratch buffer, absorbs their leaf tags into the
// trunk aggregation transcript, and advances the leaf counter. src and dst
// must each be exactly n*ChunkSize bytes. It reports whether a kernel ran; on
// amd64 one always does.
func encryptChunkRun(c *cryptor, src, dst []byte, n int) bool {
	var s state8
	initChunks(&s, c.key[:], c.nonce[:], c.nLeaves+1)
	var tags [256]byte
	if cpuid.HasAVX512 {
		encryptChunksBodyAVX512N(&s, &src[0], &dst[0], uint64(n))
	} else {
		encryptChunksBodyAVX2N(&s, &src[0], &dst[0], uint64(n))
	}
	finishEncryptChunksN(&s, src, dst, &tags, n)
	c.trunk.absorbMore(tags[:n*leafTagSize], aggMore)
	c.nLeaves += uint64(n)
	return true
}

// decryptChunkRun is the decrypt counterpart of encryptChunkRun.
func decryptChunkRun(c *cryptor, src, dst []byte, n int) bool {
	var s state8
	initChunks(&s, c.key[:], c.nonce[:], c.nLeaves+1)
	var tags [256]byte
	if cpuid.HasAVX512 {
		decryptChunksBodyAVX512N(&s, &src[0], &dst[0], uint64(n))
	} else {
		decryptChunksBodyAVX2N(&s, &src[0], &dst[0], uint64(n))
	}
	finishDecryptChunksN(&s, src, dst, &tags, n)
	c.trunk.absorbMore(tags[:n*leafTagSize], aggMore)
	c.nLeaves += uint64(n)
	return true
}
