package tw128

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// TestAggPathAgainstReference cross-checks the multi-leaf (x8 SIMD cascade)
// path against the Python reference for message sizes that exercise the full
// x8, x8+x1, padded-x8, and multi-x8 cases.
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
		// Sizes are k×ChunkSize (8183) ± ε, chosen to exercise padded-x8 (7
		// leaves), full x8 (8 leaves), x8+x1, and multi-x8 (16/21 leaves).
		{65464, "d7c72a400e48b64e60d7fc7582b8bc71d74857f06e2622061e2c30a06f765b54", "624b7c9180e2be8029582540b9ab664de2a6f420ce74fd1c646bb954b2a9dcd2"},
		{65465, "cff0c723e8040b6cc4d782995e19250e6db8a398eef4d5e2d3c141d390d1c50a", "6f76553462803d75ce54ccadc07035b798c364e5d188e380d6460829503148b8"},
		{73647, "5d7d7ad1a33c52dc4b186aef4f5ffa41c639bad24032e994b693e07413651c86", "c251dec84c27cd01f00d1fff04b99ecfab233e20754bc96c477050df9b926892"},
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

		// Verify the x8 decrypt cascade inverts encryption and recomputes the
		// reference tag.
		pt2, tag2 := decrypt(key, nonce, ad, ct)
		if string(pt2) != string(pt) {
			t.Errorf("n=%d decrypt round-trip mismatch", tc.n)
		}
		if got := hex.EncodeToString(tag2[:]); got != tc.tagHex {
			t.Errorf("n=%d decrypt tag mismatch:\n  got  %s\n  want %s", tc.n, got, tc.tagHex)
		}
	}
}
