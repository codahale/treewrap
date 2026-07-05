package tw128

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// TestAggPathAgainstReference cross-checks the multi-leaf (x8 SIMD cascade)
// path against the Python reference for message sizes that exercise the full
// x8, x8+x1, remainder-kernel, and multi-x8 cases.
func TestAggPathAgainstReference(t *testing.T) {
	key := seq(KeySize)
	nonce := make([]byte, NonceSize)
	for i := range nonce {
		nonce[i] = byte(i + 32)
	}
	ad := []byte("agg path")

	sample := func(n int) []byte {
		b := make([]byte, n)
		for i := range b {
			b[i] = byte((17*i + 31) % 256)
		}
		return b
	}

	cases := []struct {
		n      int
		ctSHA  string
		tagHex string
	}{
		// Sizes are k×ChunkSize (8183) ± ε, chosen to exercise the remainder
		// kernels (7 leaves), full x8 (8 leaves), x8+x1, and multi-x8 (16/21
		// leaves).
		{16365, "40c4265bb293f3a0f454b41d0a02ad4f65567527a460a763180879fa00f5d6d8", "4ee67fb6cbfcf15affad0be7025e38da7d7937ab6242e452ab85776c2d9aba07"},
		{32731, "a5c738c557459075841efd00fcc7eaffba75c32f454b5055623479dd2620b995", "a46cebba0dbd7b635281e677be91f53a81dddfeb46e6dffea4d3fec893df00aa"},
		{49097, "9d0d15f8c33b233ad1671bf218bcfa7935cbca3ebf38f6ca1cda2258b0ffe0fa", "91af59d21149ab02d220ef5e55e339967346de51ba4059d3606a4e167cf83b08"},
		{65464, "d7c72a400e48b64e60d7fc7582b8bc71d74857f06e2622061e2c30a06f765b54", "624b7c9180e2be8029582540b9ab664de2a6f420ce74fd1c646bb954b2a9dcd2"},
		{65465, "cff0c723e8040b6cc4d782995e19250e6db8a398eef4d5e2d3c141d390d1c50a", "6f76553462803d75ce54ccadc07035b798c364e5d188e380d6460829503148b8"},
		{73647, "5d7d7ad1a33c52dc4b186aef4f5ffa41c639bad24032e994b693e07413651c86", "c251dec84c27cd01f00d1fff04b99ecfab233e20754bc96c477050df9b926892"},
		{81829, "3ad077e1faa1573097647e82a4964cb9f5b42ff0411137b440bacaef87f19a80", "d6d215e72eb637cf439536bed4073ba74d76d3bb7a6c507b4275f83c5400b5e8"},
		{106456, "ddd16bee3d96edfe2e9714b7c4978e987ac6e2ac18e270dd854a367b16d57ba4", "b6f9dabece0c23a29accfa1913a691d8af212c5ec2cecbfc7d622eaf587b62f5"},
		{130928, "d0abe0dfe5240c4ca588f7aee9b7ac9fb3959ac92e4cb116a9e38ddff67fd0d1", "02c41867bed0a52aeba9df45c4e14612176f389912bfe072f79a2ddfa941f4f9"},
		{171848, "8f0bdda8cba6a818d05243564efded69757566b05b9cde55b76813a22ddca6e4", "821e4b4cdc6d44e1e7d49cb38de4c42e6383696a67c0368f4cb1d317a1d27c03"},
	}

	for _, tc := range cases {
		pt := sample(tc.n)
		ct, tag := encrypt(key, nonce, ad, pt)
		sum := sha256.Sum256(ct)
		if got := hex.EncodeToString(sum[:]); got != tc.ctSHA {
			t.Errorf("n=%d ciphertext sha mismatch:\n  got  %s\n  want %s", tc.n, got, tc.ctSHA)
		}
		if got := hex.EncodeToString(tag[:]); got != tc.tagHex {
			t.Errorf("n=%d tag mismatch:\n  got  %s\n  want %s", tc.n, got, tc.tagHex)
		}

		// Verify the x8 decrypt cascade inverts encryption and authenticates
		// against the reference tag.
		refTag, err := hex.DecodeString(tc.tagHex)
		if err != nil {
			t.Fatalf("n=%d bad reference tag: %v", tc.n, err)
		}
		var etag [TagSize]byte
		copy(etag[:], refTag)
		pt2, err := decrypt(key, nonce, ad, ct, etag)
		if err != nil {
			t.Errorf("n=%d Open rejected the reference ciphertext: %v", tc.n, err)
		} else if string(pt2) != string(pt) {
			t.Errorf("n=%d decrypt round-trip mismatch", tc.n)
		}
	}
}
