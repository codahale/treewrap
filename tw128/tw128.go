// Package tw128 implements TW128, a tree-parallel authenticated encryption algorithm based on keyed duplexes.
//
// WARNING: TreeWrap/TW128 is an unreviewed research construction. This package
// is hazmat code, not a production cryptographic library. It has not been
// audited, standardized, or hardened for deployment, and it should not be used
// to protect real data.
//
// This package exists to support the accompanying paper, experiments, test
// vectors, and benchmarks.
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

type cryptor struct {
	key       [KeySize]byte
	nonce     [NonceSize]byte
	trunk     duplex // trunk (root) duplex state
	leaf      duplex // current leaf duplex state (chunks 1+)
	nLeaves   uint64 // number of completed leaves
	chunkOff  int    // bytes processed in current chunk
	leafMode  bool   // true after chunk 0 body complete
	finalized bool
	decrypt   bool
}

func (c *cryptor) initCryptor(key, nonce, ad []byte, decrypt bool) {
	checkSize("key", key, KeySize)
	checkSize("nonce", nonce, NonceSize)
	copy(c.key[:], key)
	copy(c.nonce[:], nonce)
	c.decrypt = decrypt

	// Root init (INIT_LAST). When associated data is present, run the
	// associated-data phase; its closing AD_LAST block leaves the first
	// chunk-0 keystream block in the rate. When the associated data is empty,
	// the phase is elided: initWith already left the chunk-0 keystream block
	// in the rate, mirroring leaf init.
	p := rootInit(c.key[:], c.nonce[:])
	c.trunk.initWith(p[:])
	if len(ad) > 0 {
		c.trunk.absorbMore(ad, adMore)
		c.trunk.closeBlock(adLast)
	}
}

// finalizeLeaf closes the current leaf's MSG_LAST block, then absorbs its tag
// into the trunk's aggregation transcript.
func (c *cryptor) finalizeLeaf() {
	c.leaf.closeBlock(msgLast)
	tag := c.leaf.tagBytes()
	c.trunk.absorbMore(tag[:], aggMore)
	c.nLeaves++
	c.chunkOff = 0
}

// transitionToLeafMode closes the trunk's chunk-0 message phase and enters leaf
// mode, leaving the trunk ready to absorb the leaf-tag aggregation transcript.
func (c *cryptor) transitionToLeafMode() {
	c.trunk.closeBlock(msgLast)
	c.leafMode = true
	c.chunkOff = 0
}

func (c *cryptor) finalizeInternal() [TagSize]byte {
	if c.finalized {
		panic("tw128: Finalize called more than once")
	}
	c.finalized = true

	// If still on chunk 0 (a single chunk, no leaves), close the trunk message
	// phase and elide the aggregation phase: the closing MSG_LAST call emits
	// the root tag directly, mirroring a leaf. This covers the empty-message
	// case.
	if !c.leafMode {
		c.trunk.closeBlock(msgLast)
		var tag [TagSize]byte
		c.trunk.extractTag(&tag)
		return tag
	}

	// Finalize the last leaf if a partial chunk is in progress.
	if c.leafMode && c.chunkOff > 0 {
		c.finalizeLeaf()
	}

	// Aggregation phase: leaf tags were absorbed incrementally; append the
	// little-endian leaf count and close with AGG_LAST. The closing block's
	// keystream prefix is the root tag.
	var cnt [8]byte
	binary.LittleEndian.PutUint64(cnt[:], c.nLeaves)
	c.trunk.absorbMore(cnt[:], aggMore)
	c.trunk.closeBlock(aggLast)

	var tag [TagSize]byte
	c.trunk.extractTag(&tag)
	return tag
}

func (c *cryptor) xorKeyStream(dst, src []byte) {
	if len(src) == 0 {
		return
	}

	if !c.leafMode {
		// Still on chunk 0 (the root message phase).
		n := min(len(src), ChunkSize-c.chunkOff)
		c.trunk.bodyMore(dst[:n], src[:n], c.decrypt, msgMore)
		c.chunkOff += n
		dst = dst[n:]
		src = src[n:]

		if c.chunkOff == ChunkSize && len(src) > 0 {
			c.transitionToLeafMode()
		}

		if len(src) == 0 {
			return
		}
	}

	// Leaf mode: processing chunks 1..n-1.

	// Continue an in-progress partial leaf chunk.
	if c.chunkOff > 0 {
		n := min(len(src), ChunkSize-c.chunkOff)
		c.leaf.bodyMore(dst[:n], src[:n], c.decrypt, msgMore)
		c.chunkOff += n
		dst = dst[n:]
		src = src[n:]

		if c.chunkOff == ChunkSize {
			c.finalizeLeaf()
		}
	}

	// Process complete leaf chunks via SIMD cascade.
	if nComplete := len(src) / ChunkSize; nComplete > 0 {
		c.processComplete(dst[:nComplete*ChunkSize], src[:nComplete*ChunkSize], nComplete)
		dst = dst[nComplete*ChunkSize:]
		src = src[nComplete*ChunkSize:]
	}

	// Start a new partial leaf chunk with remaining bytes.
	if len(src) > 0 {
		p := leafInit(c.key[:], c.nonce[:], c.nLeaves+1)
		c.leaf.initWith(p[:])
		c.chunkOff = 0
		c.leaf.bodyMore(dst[:len(src)], src, c.decrypt, msgMore)
		c.chunkOff += len(src)
	}
}

// processComplete processes nFlush complete leaf chunks via x8 SIMD with padding for remainders.
func (c *cryptor) processComplete(dst, src []byte, nFlush int) {
	idx := 0

	var tags [256]byte
	for idx+8 <= nFlush {
		off := idx * ChunkSize
		if c.decrypt {
			decryptChunks(c.key[:], c.nonce[:], c.nLeaves+1, src[off:off+8*ChunkSize], dst[off:off+8*ChunkSize], &tags)
		} else {
			encryptChunks(c.key[:], c.nonce[:], c.nLeaves+1, src[off:off+8*ChunkSize], dst[off:off+8*ChunkSize], &tags)
		}
		c.trunk.absorbMore(tags[:], aggMore)
		c.nLeaves += 8
		idx += 8
	}

	// 2-wide pass: drain the remaining complete chunks in pairs where a 2-wide
	// kernel is available (arm64). This avoids the x1 serial penalty for small
	// remainders (e.g. the three leaf chunks of a 32 KiB message). On
	// platforms without a 2-wide kernel the calls report false and the
	// register-resident and x1 passes below handle the remainder.
	for idx+2 <= nFlush {
		off := idx * ChunkSize
		var ok bool
		if c.decrypt {
			ok = decryptChunkPair(c, src[off:off+2*ChunkSize], dst[off:off+2*ChunkSize])
		} else {
			ok = encryptChunkPair(c, src[off:off+2*ChunkSize], dst[off:off+2*ChunkSize])
		}
		if !ok {
			break
		}
		idx += 2
	}

	// Remainder pass: drain a 2..7 chunk remainder with a single kernel call
	// that reads the chunks directly (no scratch buffer): register-resident
	// masked gather/scatter on AVX-512, dummy-lane x4 on AVX2. This removes
	// the x1 serial penalty for a small remainder (e.g. the three leaf chunks
	// of a 32 KiB message).
	//
	// This pass also takes the tail of a larger message (idx > 0), whose
	// chunks are cold: the kernels read each chunk as a sequential stream, so
	// cold tails prefetch as well as the x8 batches do. Measured on Emerald
	// Rapids (Xeon Platinum 8581C), the AVX-512 kernel beats both a padded-x8
	// pass and serial x1 for every remainder size, on cache-resident and cold
	// chunks alike; see the commit introducing this pass for the measurements.
	// On arm64 the pair pass already left fewer than two chunks; on platforms
	// without a remainder kernel the call reports false and the x1 loop below
	// runs.
	if rem := nFlush - idx; rem >= 2 {
		off := idx * ChunkSize
		var ok bool
		if c.decrypt {
			ok = decryptChunkRun(c, src[off:off+rem*ChunkSize], dst[off:off+rem*ChunkSize], rem)
		} else {
			ok = encryptChunkRun(c, src[off:off+rem*ChunkSize], dst[off:off+rem*ChunkSize], rem)
		}
		if ok {
			idx += rem
		}
	}

	// Remainder via x1: a single leftover chunk, or any remainder on platforms
	// without SIMD chunk kernels — where padding to 8 wide would buy nothing,
	// since the generic 8-way permute is eight serial permutes.
	for idx < nFlush {
		off := idx * ChunkSize
		if c.decrypt {
			decryptX1(c.key[:], c.nonce[:], c.nLeaves+1, src[off:off+ChunkSize], dst[off:off+ChunkSize], &c.leaf)
		} else {
			encryptX1(c.key[:], c.nonce[:], c.nLeaves+1, src[off:off+ChunkSize], dst[off:off+ChunkSize], &c.leaf)
		}
		tag := c.leaf.tagBytes()
		c.trunk.absorbMore(tag[:], aggMore)
		c.nLeaves++
		idx++
	}
}

// Encryptor incrementally encrypts data and computes the authentication tag.
type Encryptor struct {
	cryptor
}

// NewEncryptor returns a new Encryptor initialized with the given key, nonce, and associated data.
func NewEncryptor(key, nonce, ad []byte) (e Encryptor) {
	e.initCryptor(key, nonce, ad, false)
	return e
}

// XORKeyStream encrypts src into dst. Dst and src must overlap entirely or not at all. Len(dst) must be >= len(src).
func (e *Encryptor) XORKeyStream(dst, src []byte) { e.xorKeyStream(dst, src) }

// Finalize returns the authentication tag.
func (e *Encryptor) Finalize() [TagSize]byte {
	return e.finalizeInternal()
}

// Decryptor incrementally decrypts data and computes the authentication tag.
type Decryptor struct {
	cryptor
}

// NewDecryptor returns a new Decryptor initialized with the given key, nonce, and associated data.
func NewDecryptor(key, nonce, ad []byte) (d Decryptor) {
	d.initCryptor(key, nonce, ad, true)
	return d
}

// XORKeyStream decrypts src into dst. Dst and src must overlap entirely or not at all. Len(dst) must be >= len(src).
func (d *Decryptor) XORKeyStream(dst, src []byte) { d.xorKeyStream(dst, src) }

// Finalize returns the expected authentication tag.
func (d *Decryptor) Finalize() [TagSize]byte {
	return d.finalizeInternal()
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
