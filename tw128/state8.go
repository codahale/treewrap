package tw128

import "encoding/binary"

// state8 is eight lane-major Keccak-p[1600] duplex states sharing a block
// position. The eight instances run identically sized leaf chunks in lockstep,
// so a single pos tracks the sigma bytes in the current block for all of them.
type state8 struct {
	a   [lanes][8]uint64
	pos int
}

func permute12x8Generic(s *state8) {
	var t [lanes]uint64
	for inst := range 8 {
		for lane := range lanes {
			t[lane] = s.a[lane][inst]
		}
		keccakP1600x12(&t)
		for lane := range lanes {
			s.a[lane][inst] = t[lane]
		}
	}
}

func (s *state8) permute12() {
	if permute12x8Arch(s) {
		return
	}
	permute12x8Generic(s)
}

// closeBlock terminates the current block for all eight instances with the
// combined suffix byte and trailing pad bit, permutes, and resets pos.
func (s *state8) closeBlock(suffix byte) {
	for inst := range 8 {
		xorByteInWord(&s.a[s.pos>>3][inst], s.pos, suffix)
		xorByteInWord(&s.a[(rate-1)>>3][inst], rate-1, 0x80)
	}
	s.permute12()
	s.pos = 0
}

// encryptBlock encrypts plaintext src into ciphertext dst for instance inst at
// the start of the current block, absorbing the ciphertext into the rate.
func (s *state8) encryptBlock(inst int, src, dst []byte) {
	full := len(src) >> 3
	if full > 0 {
		_ = src[full*8-1] // BCE hint
		_ = dst[full*8-1] // BCE hint
	}
	for i := range full {
		base := i << 3
		c := binary.LittleEndian.Uint64(src[base:base+8]) ^ s.a[i][inst]
		s.a[i][inst] ^= c
		binary.LittleEndian.PutUint64(dst[base:base+8], c)
	}
	if rem := len(src) & 7; rem > 0 {
		base := full << 3
		c := loadPartialLE(src[base:base+rem]) ^ (s.a[full][inst] & mask64(rem))
		s.a[full][inst] ^= c
		storePartialLE(dst[base:base+rem], c)
	}
}

// decryptBlock decrypts ciphertext src into plaintext dst for instance inst at
// the start of the current block, absorbing the ciphertext into the rate.
func (s *state8) decryptBlock(inst int, src, dst []byte) {
	full := len(src) >> 3
	if full > 0 {
		_ = src[full*8-1] // BCE hint
		_ = dst[full*8-1] // BCE hint
	}
	for i := range full {
		base := i << 3
		c := binary.LittleEndian.Uint64(src[base : base+8])
		p := c ^ s.a[i][inst]
		s.a[i][inst] ^= c
		binary.LittleEndian.PutUint64(dst[base:base+8], p)
	}
	if rem := len(src) & 7; rem > 0 {
		base := full << 3
		c := loadPartialLE(src[base : base+rem])
		p := c ^ (s.a[full][inst] & mask64(rem))
		s.a[full][inst] ^= c
		storePartialLE(dst[base:base+rem], p)
	}
}
