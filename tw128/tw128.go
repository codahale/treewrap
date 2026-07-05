// Package tw128 implements TW128, a tree-parallel authenticated encryption algorithm based on keyed duplexes.
//
// WARNING: TreeWrap/TW128 is an unreviewed research construction. This package
// is hazmat code, not a production cryptographic library. It has not been
// audited, standardized, or hardened for deployment, and it should not be used
// to protect real data.
//
// This package exists to support the accompanying paper, experiments, test
// vectors, and benchmarks. Its API is the cipher.AEAD returned by New: Seal
// appends a TagSize-byte authentication tag and Open verifies it in constant
// time.
//
// The trunk (root) duplex handles associated-data absorption, encryption of
// chunk 0, absorption of the later hidden leaf tags, and final authentication
// tag extraction. Later chunks are processed by independent leaf transcripts
// under domain-separated chunk IDs.
//
// Each duplex is a strict BDPV11 duplex over Keccak-p[1600,12]: the root is
// initialized with "TW128R" || K || N and each leaf with "TW128L" || K || N ||
// le64(j). Every duplexing call absorbs at most rhoBytes of sigma followed by a
// 4-bit domain suffix and pad10*1, then permutes once.
package tw128

import (
	"encoding/binary"
)

const (
	// KeySize is the size of the key in bytes.
	KeySize = 32

	// NonceSize is the size of the nonce in bytes.
	NonceSize = 32

	// TagSize is the size of the authentication tag in bytes.
	TagSize = 32

	// ChunkSize is the size of each chunk in bytes. 8183 = 49 × rhoBytes (167),
	// so a chunk splits into exactly 49 full rho-blocks with no ragged tail.
	ChunkSize = 8183

	// leafTagSize is the size of each hidden leaf tag in bytes.
	leafTagSize = 32

	// prefixLen is the length of the role-distinguishing init prefix.
	prefixLen = 6

	// rootInitLen and leafInitLen are the lengths of the init sigma blocks.
	rootInitLen = prefixLen + KeySize + NonceSize
	leafInitLen = prefixLen + KeySize + NonceSize + 8
)

// Combined duplex suffix bytes. Each is the 4-bit domain suffix OR'd with the
// pad10*1 start bit (0x10); closeBlock XORs the trailing 0x80 pad bit.
const (
	initLast = 0x1C // 0x0C | 0x10
	adMore   = 0x19 // 0x09 | 0x10
	adLast   = 0x1D // 0x0D | 0x10
	msgMore  = 0x1A // 0x0A | 0x10
	msgLast  = 0x1E // 0x0E | 0x10
	aggMore  = 0x1B // 0x0B | 0x10
	aggLast  = 0x1F // 0x0F | 0x10
)

var (
	rootPrefix = [prefixLen]byte{'T', 'W', '1', '2', '8', 'R'}
	leafPrefix = [prefixLen]byte{'T', 'W', '1', '2', '8', 'L'}
)

// rootInit builds the root duplex init sigma: "TW128R" || key || nonce.
func rootInit(key, nonce []byte) [rootInitLen]byte {
	var p [rootInitLen]byte
	copy(p[:prefixLen], rootPrefix[:])
	copy(p[prefixLen:prefixLen+KeySize], key)
	copy(p[prefixLen+KeySize:], nonce)
	return p
}

// leafInit builds a leaf duplex init sigma: "TW128L" || key || nonce ||
// le64(chunkID).
func leafInit(key, nonce []byte, chunkID uint64) [leafInitLen]byte {
	var p [leafInitLen]byte
	copy(p[:prefixLen], leafPrefix[:])
	copy(p[prefixLen:prefixLen+KeySize], key)
	copy(p[prefixLen+KeySize:prefixLen+KeySize+NonceSize], nonce)
	binary.LittleEndian.PutUint64(p[prefixLen+KeySize+NonceSize:], chunkID)
	return p
}

// aggregator carries the state shared between the one-shot pipeline and the
// leaf-cascade kernels: the trunk duplex absorbing the leaf tags, the key and
// nonce for leaf inits, and the count of completed leaves. The trunk is held
// by value so the zero aggregator is valid and no field escapes to the heap.
type aggregator struct {
	key     [KeySize]byte
	nonce   [NonceSize]byte
	trunk   duplex // trunk (root) duplex state
	nLeaves uint64 // number of completed leaves
	decrypt bool
}

// crypt runs the one-shot TW128 pipeline over src into dst and returns the
// root tag. dst and src must be the same length and must overlap entirely or
// not at all. decrypt selects the SpongeWrap direction (the ciphertext is
// absorbed either way).
func crypt(key, nonce, ad, dst, src []byte, decrypt bool) [TagSize]byte {
	checkSize("key", key, KeySize)
	checkSize("nonce", nonce, NonceSize)

	var g aggregator
	copy(g.key[:], key)
	copy(g.nonce[:], nonce)
	g.decrypt = decrypt

	// Root init (INIT_LAST). When associated data is present, run the
	// associated-data phase; its closing AD_LAST block leaves the first
	// chunk-0 keystream block in the rate. When the associated data is empty,
	// the phase is elided: initWith already left the chunk-0 keystream block
	// in the rate, mirroring leaf init.
	p := rootInit(g.key[:], g.nonce[:])
	g.trunk.initWith(p[:])
	if len(ad) > 0 {
		g.trunk.absorbMore(ad, adMore)
		g.trunk.closeBlock(adLast)
	}

	// A message that fits in chunk 0 (including the empty message) is the
	// trunk message phase alone, closed with MSG_LAST, and the aggregation
	// phase is elided: the closing MSG_LAST block emits the root tag
	// directly, mirroring a leaf.
	if len(src) <= ChunkSize {
		g.trunk.bodyMore(dst, src, decrypt, msgMore)
		g.trunk.closeBlock(msgLast)
		var tag [TagSize]byte
		g.trunk.extractTag(&tag)
		return tag
	}

	g.processMultiChunk(dst, src)

	// Aggregation phase: leaf tags were absorbed in leaf order; append the
	// little-endian leaf count and close with AGG_LAST. The closing block's
	// keystream prefix is the root tag.
	var cnt [8]byte
	binary.LittleEndian.PutUint64(cnt[:], g.nLeaves)
	g.trunk.absorbMore(cnt[:], aggMore)
	g.trunk.closeBlock(aggLast)

	var tag [TagSize]byte
	g.trunk.extractTag(&tag)
	return tag
}

func decryptX1(key, nonce []byte, index uint64, ct, pt []byte, d *duplex) {
	p := leafInit(key, nonce, index)
	d.initWith(p[:])
	d.bodyMore(pt, ct, true, msgMore)
	d.closeBlock(msgLast)
}

func encryptX1(key, nonce []byte, index uint64, pt, ct []byte, d *duplex) {
	p := leafInit(key, nonce, index)
	d.initWith(p[:])
	d.bodyMore(ct, pt, false, msgMore)
	d.closeBlock(msgLast)
}

func checkSize(name string, got []byte, want int) {
	if len(got) != want {
		panic("tw128: invalid " + name + " size")
	}
}
