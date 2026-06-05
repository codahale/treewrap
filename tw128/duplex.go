package tw128

import "encoding/binary"

// duplex is the TW128 strict-BDPV11 duplex over Keccak-p[1600,12] with c=256,
// r=1344. Each duplexing call absorbs at most rhoBytes of sigma followed by a
// 4-bit domain suffix and pad10*1, then permutes. pos counts the sigma bytes
// accumulated in the current block.
type duplex struct {
	a   [lanes]uint64
	pos int
}

func permute12x1Generic(d *duplex) {
	keccakP1600x12(&d.a)
}

func (d *duplex) permute12() {
	if permute12x1Arch(d) {
		return
	}
	permute12x1Generic(d)
}

// closeBlock terminates the current block: it XORs the combined suffix byte
// (the 4-bit domain suffix already OR'd with the pad10*1 start bit) at the
// current position, sets the trailing pad bit, permutes, and resets pos. After
// it returns the first rhoBytes of state are the next keystream block.
func (d *duplex) closeBlock(suffix byte) {
	xorByteInWord(&d.a[d.pos>>3], d.pos, suffix)
	xorByteInWord(&d.a[(rate-1)>>3], rate-1, 0x80)
	d.permute12()
	d.pos = 0
}

// initWith loads an init prefix (always shorter than rhoBytes) into a cleared
// state and closes the block with INIT_LAST.
func (d *duplex) initWith(prefix []byte) {
	clear(d.a[:])
	full := len(prefix) >> 3
	for lane := range full {
		d.a[lane] = binary.LittleEndian.Uint64(prefix[lane<<3 : lane<<3+8])
	}
	if rem := len(prefix) & 7; rem > 0 {
		off := full << 3
		d.a[full] = loadPartialLE(prefix[off : off+rem])
	}
	d.pos = len(prefix)
	d.closeBlock(initLast)
}

// xorBytesAt XORs data into the rate starting at byte offset pos. The caller
// guarantees pos+len(data) <= rate.
func (d *duplex) xorBytesAt(pos int, data []byte) {
	lane := pos >> 3
	if off := pos & 7; off != 0 {
		n := min(8-off, len(data))
		d.a[lane] ^= loadPartialLE(data[:n]) << (uint(off) << 3)
		data = data[n:]
		lane++
		if len(data) == 0 {
			return
		}
	}
	full := len(data) >> 3
	for i := range full {
		base := i << 3
		d.a[lane+i] ^= binary.LittleEndian.Uint64(data[base : base+8])
	}
	if rem := len(data) & 7; rem > 0 {
		base := full << 3
		d.a[lane+full] ^= loadPartialLE(data[base : base+rem])
	}
}

// absorbMore absorbs data across rhoBytes-sized blocks. Blocks that fill before
// the data is exhausted are closed with moreSuffix; the final (possibly
// partial, possibly full) block is left open for the caller to close with the
// matching LAST suffix.
func (d *duplex) absorbMore(data []byte, moreSuffix byte) {
	for len(data) > 0 {
		if d.pos == rhoBytes {
			d.closeBlock(moreSuffix)
		}
		n := min(rhoBytes-d.pos, len(data))
		d.xorBytesAt(d.pos, data[:n])
		d.pos += n
		data = data[n:]
	}
}

// bodyMore runs SpongeWrap over src across rhoBytes-sized blocks, absorbing the
// ciphertext in both directions. Full blocks are closed with moreSuffix; the
// final block is left open for the caller to close with MSG_LAST.
func (d *duplex) bodyMore(dst, src []byte, decrypt bool, moreSuffix byte) {
	for len(src) > 0 {
		if d.pos == rhoBytes {
			d.closeBlock(moreSuffix)
		}
		n := min(rhoBytes-d.pos, len(src))
		if decrypt {
			d.decryptAt(d.pos, src[:n], dst[:n])
		} else {
			d.encryptAt(d.pos, src[:n], dst[:n])
		}
		d.pos += n
		src = src[n:]
		dst = dst[n:]
	}
}

// encryptAt encrypts plaintext src into ciphertext dst at byte offset pos,
// absorbing the ciphertext into the rate.
func (d *duplex) encryptAt(pos int, src, dst []byte) {
	lane := pos >> 3
	if off := pos & 7; off != 0 {
		n := min(8-off, len(src))
		shift := uint(off) << 3
		k := (d.a[lane] >> shift) & mask64(n)
		c := loadPartialLE(src[:n]) ^ k
		d.a[lane] ^= c << shift
		storePartialLE(dst[:n], c)
		src = src[n:]
		dst = dst[n:]
		lane++
		if len(src) == 0 {
			return
		}
	}
	full := len(src) >> 3
	for i := range full {
		base := i << 3
		c := binary.LittleEndian.Uint64(src[base:base+8]) ^ d.a[lane+i]
		d.a[lane+i] ^= c
		binary.LittleEndian.PutUint64(dst[base:base+8], c)
	}
	if rem := len(src) & 7; rem > 0 {
		base := full << 3
		c := loadPartialLE(src[base:base+rem]) ^ (d.a[lane+full] & mask64(rem))
		d.a[lane+full] ^= c
		storePartialLE(dst[base:base+rem], c)
	}
}

// decryptAt decrypts ciphertext src into plaintext dst at byte offset pos,
// absorbing the ciphertext into the rate.
func (d *duplex) decryptAt(pos int, src, dst []byte) {
	lane := pos >> 3
	if off := pos & 7; off != 0 {
		n := min(8-off, len(src))
		shift := uint(off) << 3
		k := (d.a[lane] >> shift) & mask64(n)
		c := loadPartialLE(src[:n])
		d.a[lane] ^= c << shift
		storePartialLE(dst[:n], c^k)
		src = src[n:]
		dst = dst[n:]
		lane++
		if len(src) == 0 {
			return
		}
	}
	full := len(src) >> 3
	for i := range full {
		base := i << 3
		c := binary.LittleEndian.Uint64(src[base : base+8])
		p := c ^ d.a[lane+i]
		d.a[lane+i] ^= c
		binary.LittleEndian.PutUint64(dst[base:base+8], p)
	}
	if rem := len(src) & 7; rem > 0 {
		base := full << 3
		c := loadPartialLE(src[base : base+rem])
		p := c ^ (d.a[lane+full] & mask64(rem))
		d.a[lane+full] ^= c
		storePartialLE(dst[base:base+rem], p)
	}
}

// tagBytes returns the current keystream's first TagSize bytes, i.e. the leaf
// tag exposed after closing a leaf's MSG_LAST block.
func (d *duplex) tagBytes() [leafTagSize]byte {
	var t [leafTagSize]byte
	for lane := range leafTagSize / 8 {
		binary.LittleEndian.PutUint64(t[lane<<3:lane<<3+8], d.a[lane])
	}
	return t
}

// extractTag writes the TagSize-byte root tag (the current keystream prefix).
func (d *duplex) extractTag(tag *[TagSize]byte) {
	for lane := range TagSize / 8 {
		binary.LittleEndian.PutUint64(tag[lane<<3:lane<<3+8], d.a[lane])
	}
}
