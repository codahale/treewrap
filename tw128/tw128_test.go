package tw128

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// encrypt is a convenience helper for tests: single-call encrypt via streaming API.
func encrypt(key, nonce, ad, pt []byte) ([]byte, [TagSize]byte) {
	ct := make([]byte, len(pt))
	e := NewEncryptor(key, nonce, ad)
	e.XORKeyStream(ct, pt)
	return ct, e.Finalize()
}

// decrypt is a convenience helper for tests: single-call decrypt via streaming API.
func decrypt(key, nonce, ad, ct []byte) ([]byte, [TagSize]byte) {
	pt := make([]byte, len(ct))
	d := NewDecryptor(key, nonce, ad)
	d.XORKeyStream(pt, ct)
	return pt, d.Finalize()
}

type vectorFile struct {
	Vectors []vector `json:"vectors"`
}

type vector struct {
	Name          string `json:"name"`
	KeyHex        string `json:"key_hex"`
	NonceHex      string `json:"nonce_hex"`
	ADHex         string `json:"ad_hex"`
	PlaintextHex  string `json:"plaintext_hex"`
	CiphertextHex string `json:"ciphertext_hex"`
}

func TestVectors(t *testing.T) {
	for _, v := range loadVectors(t) {
		t.Run(v.Name, func(t *testing.T) {
			key := decodeHex(t, "key", v.KeyHex)
			nonce := decodeHex(t, "nonce", v.NonceHex)
			ad := decodeHex(t, "ad", v.ADHex)
			pt := decodeHex(t, "plaintext", v.PlaintextHex)
			expectedCTTag := decodeHex(t, "ciphertext", v.CiphertextHex)
			if len(expectedCTTag) < TagSize {
				t.Fatalf("ciphertext too short: got %d bytes, need at least %d", len(expectedCTTag), TagSize)
			}
			expectedCT := expectedCTTag[:len(expectedCTTag)-TagSize]
			expectedTag := expectedCTTag[len(expectedCTTag)-TagSize:]

			ct, tag := encrypt(key, nonce, ad, pt)

			if !bytes.Equal(tag[:], expectedTag) {
				t.Fatalf("tag mismatch:\n  got  %x\n  want %x", tag[:], expectedTag)
			}

			if !bytes.Equal(ct, expectedCT) {
				t.Fatalf("ciphertext mismatch at byte %d", firstMismatch(ct, expectedCT))
			}

			pt2, tag2 := decrypt(key, nonce, ad, ct)
			if !bytes.Equal(pt2, pt) {
				t.Fatal("round-trip plaintext mismatch")
			}
			if subtle.ConstantTimeCompare(tag[:], tag2[:]) != 1 {
				t.Fatal("round-trip tag mismatch")
			}
		})
	}
}

func loadVectors(t *testing.T) []vector {
	t.Helper()

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to locate tw128_test.go")
	}

	path := filepath.Join(filepath.Dir(file), "..", "tw128_vectors.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	var vf vectorFile
	if err := json.Unmarshal(data, &vf); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	if len(vf.Vectors) == 0 {
		t.Fatalf("no vectors found in %s", path)
	}

	return vf.Vectors
}

func TestRoundTrip(t *testing.T) {
	key := seq(KeySize)
	nonce := seq(NonceSize)

	sizes := []struct {
		name string
		size int
	}{
		{"empty", 0},
		{"1 byte", 1},
		{"167 bytes", 167},
		{"168 bytes (1 rate block)", 168},
		{"169 bytes", 169},
		{"335 bytes", 335},
		{"336 bytes (2 rate blocks)", 336},
		{fmt.Sprintf("%d bytes (chunk-1)", ChunkSize-1), ChunkSize - 1},
		{fmt.Sprintf("%d bytes (1 chunk)", ChunkSize), ChunkSize},
		{fmt.Sprintf("%d bytes", ChunkSize+1), ChunkSize + 1},
		{fmt.Sprintf("%d bytes (2 chunks)", ChunkSize*2), ChunkSize * 2},
		{fmt.Sprintf("%d bytes", ChunkSize*2+1), ChunkSize*2 + 1},
		{fmt.Sprintf("%d bytes (3 chunks)", ChunkSize*3), ChunkSize * 3},
		{fmt.Sprintf("%d bytes", ChunkSize*3+999), ChunkSize*3 + 999},
	}

	for _, sz := range sizes {
		t.Run(sz.name, func(t *testing.T) {
			pt := seq(sz.size)
			ad := seq(sz.size % 41)

			ct, tag := encrypt(key, nonce, ad, pt)

			if len(ct) != len(pt) {
				t.Fatalf("ciphertext length: got %d, want %d", len(ct), len(pt))
			}

			pt2, tag2 := decrypt(key, nonce, ad, ct)
			if !bytes.Equal(pt2, pt) {
				t.Fatalf("plaintext mismatch at size %d", sz.size)
			}
			if subtle.ConstantTimeCompare(tag[:], tag2[:]) != 1 {
				t.Fatalf("tag mismatch at size %d", sz.size)
			}
		})
	}
}

func TestInPlace(t *testing.T) {
	key := seq(KeySize)
	nonce := seq(NonceSize)

	for _, size := range []int{0, 1, 168, ChunkSize, ChunkSize + 1, ChunkSize * 2} {
		pt := seq(size)
		buf := make([]byte, size)
		copy(buf, pt)

		e := NewEncryptor(key, nonce, nil)
		e.XORKeyStream(buf, buf) // in-place
		tag := e.Finalize()

		d := NewDecryptor(key, nonce, nil)
		d.XORKeyStream(buf, buf) // in-place
		tag2 := d.Finalize()

		if !bytes.Equal(buf, pt) {
			t.Fatalf("in-place round-trip failed at size %d", size)
		}
		if subtle.ConstantTimeCompare(tag[:], tag2[:]) != 1 {
			t.Fatalf("in-place tag mismatch at size %d", size)
		}
	}
}

func TestIncrementalWrite(t *testing.T) {
	key := seq(KeySize)
	nonce := seq(NonceSize)
	ad := []byte("test ad")
	pt := seq(ChunkSize*2 + 500)

	// Single-call reference.
	refCT, refTag := encrypt(key, nonce, ad, pt)

	// Multi-call with various write sizes.
	for _, writeSize := range []int{1, 7, 100, 168, 169, ChunkSize - 1, ChunkSize, ChunkSize + 1} {
		t.Run(fmt.Sprintf("%d", writeSize), func(t *testing.T) {
			ct := make([]byte, len(pt))
			e := NewEncryptor(key, nonce, ad)
			off := 0
			for off < len(pt) {
				n := min(writeSize, len(pt)-off)
				e.XORKeyStream(ct[off:off+n], pt[off:off+n])
				off += n
			}
			tag := e.Finalize()

			if !bytes.Equal(ct, refCT) {
				t.Fatalf("incremental ct mismatch (writeSize=%d)", writeSize)
			}
			if tag != refTag {
				t.Fatalf("incremental tag mismatch (writeSize=%d)", writeSize)
			}
		})
	}
}

func TestWrongAD(t *testing.T) {
	key := seq(KeySize)
	nonce := seq(NonceSize)
	pt := []byte("hello")
	ad := []byte("correct")

	ct, tag := encrypt(key, nonce, ad, pt)

	_, tag2 := decrypt(key, nonce, []byte("wrong"), ct)
	if subtle.ConstantTimeCompare(tag[:], tag2[:]) == 1 {
		t.Fatal("wrong AD should produce different tag")
	}
}

func TestTamperedCiphertext(t *testing.T) {
	key := seq(KeySize)
	nonce := seq(NonceSize)
	pt := seq(1000)

	ct, tag := encrypt(key, nonce, nil, pt)
	tampered := make([]byte, len(ct))
	copy(tampered, ct)
	tampered[0] ^= 1

	_, tag2 := decrypt(key, nonce, nil, tampered)
	if subtle.ConstantTimeCompare(tag[:], tag2[:]) == 1 {
		t.Fatal("tampered ciphertext should produce different tag")
	}
}

func TestNilNonce(t *testing.T) {
	key := seq(KeySize)
	pt := seq(14)

	// nil nonce should behave the same as all-zero nonce.
	ct1, tag1 := encrypt(key, nil, nil, pt)
	ct2, tag2 := encrypt(key, make([]byte, NonceSize), nil, pt)

	if !bytes.Equal(ct1, ct2) {
		t.Fatal("nil nonce and zero nonce should produce same ciphertext")
	}
	if tag1 != tag2 {
		t.Fatal("nil nonce and zero nonce should produce same tag")
	}

}

func TestWrongKey(t *testing.T) {
	keyA := seq(KeySize)
	keyB := make([]byte, KeySize)
	for i := range keyB {
		keyB[i] = byte(i + 0x80)
	}
	nonce := seq(NonceSize)
	pt := seq(1000)

	ctA, tagA := encrypt(keyA, nonce, nil, pt)
	ctB, tagB := encrypt(keyB, nonce, nil, pt)

	if bytes.Equal(ctA, ctB) {
		t.Fatal("different keys should produce different ciphertext")
	}
	if subtle.ConstantTimeCompare(tagA[:], tagB[:]) == 1 {
		t.Fatal("different keys should produce different tags")
	}
}

func TestNonceSensitivity(t *testing.T) {
	key := seq(KeySize)
	nonceA := make([]byte, NonceSize)
	nonceB := make([]byte, NonceSize)
	for i := range nonceB {
		nonceB[i] = 0xFF
	}
	pt := seq(1000)

	ctA, tagA := encrypt(key, nonceA, nil, pt)
	ctB, tagB := encrypt(key, nonceB, nil, pt)

	if bytes.Equal(ctA, ctB) {
		t.Fatal("different nonces should produce different ciphertext")
	}
	if subtle.ConstantTimeCompare(tagA[:], tagB[:]) == 1 {
		t.Fatal("different nonces should produce different tags")
	}
}

func BenchmarkEncrypt(b *testing.B) {
	key := seq(KeySize)
	nonce := seq(NonceSize)

	for _, size := range Sizes {
		pt := make([]byte, size.N)
		ct := make([]byte, size.N)
		b.Run(size.Name, func(b *testing.B) {
			b.SetBytes(int64(size.N))
			b.ReportAllocs()
			for b.Loop() {
				e := NewEncryptor(key, nonce, nil)
				e.XORKeyStream(ct, pt)
				e.Finalize()
			}
		})
	}
}

func BenchmarkEncryptor(b *testing.B) {
	key := seq(KeySize)
	for _, size := range Sizes {
		pt := make([]byte, size.N)
		output := make([]byte, size.N)
		b.Run(size.Name, func(b *testing.B) {
			b.SetBytes(int64(size.N))
			b.ReportAllocs()
			for b.Loop() {
				e := NewEncryptor(key, nil, nil)
				e.XORKeyStream(output, pt)
				e.Finalize()
			}
		})
	}
}

func BenchmarkAESGCM(b *testing.B) {
	key := seq(KeySize)
	for _, size := range Sizes {
		nonce := make([]byte, 12)
		pt := make([]byte, size.N)
		output := make([]byte, size.N+16)
		b.Run(size.Name, func(b *testing.B) {
			b.SetBytes(int64(size.N))
			b.ReportAllocs()
			for b.Loop() {
				block, _ := aes.NewCipher(key[:])
				gcm, _ := cipher.NewGCM(block)
				gcm.Seal(output[:0], nonce, pt, nil)
			}
		})
	}
}

func BenchmarkDecryptor(b *testing.B) {
	key := seq(KeySize)
	for _, size := range Sizes {
		pt := make([]byte, size.N)
		ct, _ := encrypt(key, nil, nil, pt)
		output := make([]byte, size.N)
		b.Run(size.Name, func(b *testing.B) {
			b.SetBytes(int64(size.N))
			b.ReportAllocs()
			for b.Loop() {
				d := NewDecryptor(key, nil, nil)
				d.XORKeyStream(output, ct)
				d.Finalize()
			}
		})
	}
}

// seq returns a byte slice of length n where b[i] = byte(i).
func seq(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

func decodeHex(t *testing.T, name, s string) []byte {
	t.Helper()

	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode %s: %v", name, err)
	}

	return b
}

func firstMismatch(got, want []byte) int {
	limit := min(len(got), len(want))
	for i := range limit {
		if got[i] != want[i] {
			return i
		}
	}
	if len(got) != len(want) {
		return limit
	}
	return -1
}

type size struct {
	Name string
	N    int
}

var Sizes = []size{
	{"1B", 1},
	{"64B", 64},
	{"8KiB", 8 * 1024},
	{"32KiB", 32 * 1024},
	{"64KiB", 64 * 1024},
	{"1MiB", 1024 * 1024},
	{"16MiB", 16 * 1024 * 1024},
}
