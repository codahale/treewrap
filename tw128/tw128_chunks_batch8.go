package tw128

import (
	"encoding/binary"
)

const (
	// A chunk is processed as chunkBodyBlocks full rhoBytes blocks closed with
	// MSG_MORE, followed by one final block of chunkLastLen bytes closed with
	// MSG_LAST. chunkLastLen is always in 1..rhoBytes; when ChunkSize is an exact
	// multiple of rhoBytes (e.g. 8183 = 49×167) the final block is itself a full
	// rho-block, and there is no ragged tail.
	chunkBodyBlocks = (ChunkSize+rhoBytes-1)/rhoBytes - 1
	chunkLastLen    = ChunkSize - chunkBodyBlocks*rhoBytes
)

type leafTagBuffer [8 * leafTagSize]byte

// encryptLeafBatch8 encrypts 8 x 8183-byte chunks from src into dst,
// initializing 8 parallel leaf duplexes with key, nonce, and baseIndex+i,
// and writing the 8×32-byte leaf tags to tags.
// Src and dst must each be exactly 8 x 8183 = 65464 bytes.
func encryptLeafBatch8(key, nonce []byte, baseIndex uint64, src, dst []byte, tags *leafTagBuffer) {
	var s state8
	initLeafBatch8(&s, key, nonce, baseIndex)
	if encryptLeafBatch8Arch(&s, src, dst, tags) {
		return
	}
	encryptLeafBatch8Generic(&s, src, dst, tags)
}

// decryptLeafBatch8 decrypts 8 x 8183-byte chunks from src into dst,
// initializing 8 parallel leaf duplexes with key, nonce, and baseIndex+i,
// and writing the 8×32-byte leaf tags to tags.
// Src and dst must each be exactly 8 x 8183 = 65464 bytes.
func decryptLeafBatch8(key, nonce []byte, baseIndex uint64, src, dst []byte, tags *leafTagBuffer) {
	var s state8
	initLeafBatch8(&s, key, nonce, baseIndex)
	if decryptLeafBatch8Arch(&s, src, dst, tags) {
		return
	}
	decryptLeafBatch8Generic(&s, src, dst, tags)
}

// initLeafBatch8 initializes 8 parallel leaf duplexes with INIT_LAST, leaving the
// first keystream block of each leaf in its rate.
func initLeafBatch8(s *state8, key, nonce []byte, baseIndex uint64) {
	for lane := range lanes {
		for inst := range 8 {
			s.a[lane][inst] = 0
		}
	}

	for inst := range 8 {
		prefix := leafInit(key, nonce, baseIndex+uint64(inst))
		loadInitPrefix(s, inst, prefix[:])
	}

	s.pos = leafInitLen
	s.closeBlock(initLast)
}

// loadInitPrefix loads a leaf init prefix into instance inst of s.
func loadInitPrefix(s *state8, inst int, prefix []byte) {
	full := len(prefix) >> 3
	for lane := range full {
		s.a[lane][inst] = binary.LittleEndian.Uint64(prefix[lane<<3 : lane<<3+8])
	}
	if rem := len(prefix) & 7; rem > 0 {
		off := full << 3
		s.a[full][inst] = loadPartialLE(prefix[off : off+rem])
	}
}

func extractLeafTagsN(s *state8, tags *leafTagBuffer, n int) {
	for inst := range n {
		binary.LittleEndian.PutUint64(tags[inst*32:], s.a[0][inst])
		binary.LittleEndian.PutUint64(tags[inst*32+8:], s.a[1][inst])
		binary.LittleEndian.PutUint64(tags[inst*32+16:], s.a[2][inst])
		binary.LittleEndian.PutUint64(tags[inst*32+24:], s.a[3][inst])
	}
}

func encryptLeafBatch8Generic(s *state8, src, dst []byte, tags *leafTagBuffer) {
	for b := range chunkBodyBlocks {
		off := b * rhoBytes
		for inst := range 8 {
			base := inst*ChunkSize + off
			s.encryptBlock(inst, src[base:base+rhoBytes], dst[base:base+rhoBytes])
		}
		s.pos = rhoBytes
		s.closeBlock(msgMore)
	}
	finishEncryptLeafBatch8(s, src, dst, tags)
}

func decryptLeafBatch8Generic(s *state8, src, dst []byte, tags *leafTagBuffer) {
	for b := range chunkBodyBlocks {
		off := b * rhoBytes
		for inst := range 8 {
			base := inst*ChunkSize + off
			s.decryptBlock(inst, src[base:base+rhoBytes], dst[base:base+rhoBytes])
		}
		s.pos = rhoBytes
		s.closeBlock(msgMore)
	}
	finishDecryptLeafBatch8(s, src, dst, tags)
}

// finishEncryptLeafBatch8 completes the 8-way leaf batch encryption after the
// chunkBodyBlocks MSG_MORE rho-blocks have been processed.
func finishEncryptLeafBatch8(s *state8, src, dst []byte, tags *leafTagBuffer) {
	finishEncryptChunkLanes(s, src, dst, tags, 8)
}

// finishDecryptLeafBatch8 is the decrypt counterpart of finishEncryptLeafBatch8.
func finishDecryptLeafBatch8(s *state8, src, dst []byte, tags *leafTagBuffer) {
	finishDecryptChunkLanes(s, src, dst, tags, 8)
}

// finishEncryptChunkLanes completes active chunk lanes after the
// chunkBodyBlocks MSG_MORE rho-blocks have been processed (and the state stored
// into s): it encrypts the final chunkLastLen-byte block, closes it with
// MSG_LAST, and extracts the active tags. The architecture body kernels
// delegate this final block to this routine so its byte-granular handling stays
// in tested Go. When ChunkSize is an exact multiple of rhoBytes the final block
// is a full rho-block (chunkLastLen == rhoBytes).
func finishEncryptChunkLanes(s *state8, src, dst []byte, tags *leafTagBuffer, n int) {
	off := chunkBodyBlocks * rhoBytes
	for inst := range n {
		base := inst*ChunkSize + off
		s.encryptBlock(inst, src[base:base+chunkLastLen], dst[base:base+chunkLastLen])
	}
	s.pos = chunkLastLen
	s.closeBlock(msgLast)
	extractLeafTagsN(s, tags, n)
}

// finishDecryptChunkLanes is the decrypt counterpart of finishEncryptChunkLanes.
func finishDecryptChunkLanes(s *state8, src, dst []byte, tags *leafTagBuffer, n int) {
	off := chunkBodyBlocks * rhoBytes
	for inst := range n {
		base := inst*ChunkSize + off
		s.decryptBlock(inst, src[base:base+chunkLastLen], dst[base:base+chunkLastLen])
	}
	s.pos = chunkLastLen
	s.closeBlock(msgLast)
	extractLeafTagsN(s, tags, n)
}
