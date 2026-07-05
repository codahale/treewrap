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

	// Partial lane-0 fusion: for a message with chunk 0 plus a ragged first leaf,
	// process their shared full MSG_MORE body blocks together where the platform
	// has a pair kernel, then finish their different final blocks separately.
	processedAll := false
	if len(src) < 2*ChunkSize {
		tailLen := len(src) - ChunkSize
		if decrypt {
			processedAll = decryptChunk0PartialFused(&g, src, dst, tailLen)
		} else {
			processedAll = encryptChunk0PartialFused(&g, src, dst, tailLen)
		}
	}

	if !processedAll {
		// Lane-0 fusion: chunk 0 has the same kernel-visible block schedule as a
		// leaf chunk and is contiguous with leaves 1..k-1 in the message, so on
		// platforms whose kernels hand the permutation state back, the trunk's
		// chunk-0 phase rides lane 0 of the first kernel call alongside up to
		// seven leaves, eliminating the serial chunk-0 pass. The fused call
		// absorbs the leaf tags it produced and advances g.nLeaves, and reports
		// how many chunks it consumed: k on amd64, 8 or 2 on arm64 (full x8
		// batch or one NEON pair), and 0 on platforms without a fused path,
		// where the trunk processes chunk 0 serially instead. processComplete
		// then continues the cascade with g.nLeaves pre-advanced.
		fusedChunks := 0
		if nComplete := (len(src) - ChunkSize) / ChunkSize; nComplete >= 1 {
			k := min(1+nComplete, 8)
			if decrypt {
				fusedChunks = decryptChunk0Fused(&g, src[:k*ChunkSize], dst[:k*ChunkSize], k)
			} else {
				fusedChunks = encryptChunk0Fused(&g, src[:k*ChunkSize], dst[:k*ChunkSize], k)
			}
			src, dst = src[fusedChunks*ChunkSize:], dst[fusedChunks*ChunkSize:]
		}
		if fusedChunks == 0 {
			// Chunk 0: the trunk message phase, closed with MSG_LAST.
			g.trunk.bodyMore(dst[:ChunkSize], src[:ChunkSize], decrypt, msgMore)
			g.trunk.closeBlock(msgLast)
			src, dst = src[ChunkSize:], dst[ChunkSize:]
		}

		// Remaining complete leaf chunks, via the SIMD cascade.
		if n := len(src) / ChunkSize; n > 0 {
			g.processComplete(dst[:n*ChunkSize], src[:n*ChunkSize], n)
			src, dst = src[n*ChunkSize:], dst[n*ChunkSize:]
		}

		// Ragged tail: a final partial leaf of 1..ChunkSize-1 bytes.
		if len(src) > 0 {
			var leaf duplex
			if decrypt {
				decryptX1(g.key[:], g.nonce[:], g.nLeaves+1, src, dst, &leaf)
			} else {
				encryptX1(g.key[:], g.nonce[:], g.nLeaves+1, src, dst, &leaf)
			}
			t := leaf.tagBytes()
			g.trunk.absorbMore(t[:], aggMore)
			g.nLeaves++
		}
	}

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

// processComplete processes nFlush complete leaf chunks via the SIMD cascade,
// absorbing their tags into the trunk in leaf order.
func (g *aggregator) processComplete(dst, src []byte, nFlush int) {
	idx := 0

	var tags [256]byte
	for idx+8 <= nFlush {
		off := idx * ChunkSize
		if g.decrypt {
			decryptChunks(g.key[:], g.nonce[:], g.nLeaves+1, src[off:off+8*ChunkSize], dst[off:off+8*ChunkSize], &tags)
		} else {
			encryptChunks(g.key[:], g.nonce[:], g.nLeaves+1, src[off:off+8*ChunkSize], dst[off:off+8*ChunkSize], &tags)
		}
		g.trunk.absorbMore(tags[:], aggMore)
		g.nLeaves += 8
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
		if g.decrypt {
			ok = decryptChunkPair(g, src[off:off+2*ChunkSize], dst[off:off+2*ChunkSize])
		} else {
			ok = encryptChunkPair(g, src[off:off+2*ChunkSize], dst[off:off+2*ChunkSize])
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
		if g.decrypt {
			ok = decryptChunkRun(g, src[off:off+rem*ChunkSize], dst[off:off+rem*ChunkSize], rem)
		} else {
			ok = encryptChunkRun(g, src[off:off+rem*ChunkSize], dst[off:off+rem*ChunkSize], rem)
		}
		if ok {
			idx += rem
		}
	}

	// Remainder via x1: a single leftover chunk, or any remainder on platforms
	// without SIMD chunk kernels — where padding to 8 wide would buy nothing,
	// since the generic 8-way permute is eight serial permutes.
	var leaf duplex
	for idx < nFlush {
		off := idx * ChunkSize
		if g.decrypt {
			decryptX1(g.key[:], g.nonce[:], g.nLeaves+1, src[off:off+ChunkSize], dst[off:off+ChunkSize], &leaf)
		} else {
			encryptX1(g.key[:], g.nonce[:], g.nLeaves+1, src[off:off+ChunkSize], dst[off:off+ChunkSize], &leaf)
		}
		tag := leaf.tagBytes()
		g.trunk.absorbMore(tag[:], aggMore)
		g.nLeaves++
		idx++
	}
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
