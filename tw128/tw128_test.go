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

// encrypt is a convenience helper for tests: it seals pt via the public AEAD
// and splits the result into ciphertext and tag.
func encrypt(key, nonce, ad, pt []byte) ([]byte, [TagSize]byte) {
	a, err := New(key)
	if err != nil {
		panic(err)
	}
	sealed := a.Seal(nil, nonce, pt, ad)
	var tag [TagSize]byte
	copy(tag[:], sealed[len(pt):])
	return sealed[:len(pt)], tag
}

// decrypt is a convenience helper for tests: it opens ct||tag via the public
// AEAD, returning the recovered plaintext or the authentication error.
func decrypt(key, nonce, ad, ct []byte, tag [TagSize]byte) ([]byte, error) {
	a, err := New(key)
	if err != nil {
		panic(err)
	}
	sealed := append(append(make([]byte, 0, len(ct)+TagSize), ct...), tag[:]...)
	return a.Open(nil, nonce, sealed, ad)
}

type vectorFile struct {
	Comment   string          `json:"_comment"`
	Constants vectorConstants `json:"constants"`
	Vectors   []vector        `json:"vectors"`
}

type vector struct {
	Name          string `json:"name"`
	KeyHex        string `json:"key"`
	NonceHex      string `json:"nonce"`
	ADHex         string `json:"ad"`
	PlaintextHex  string `json:"plaintext"`
	CiphertextHex string `json:"ciphertext"`
	TagHex        string `json:"tag"`
}

type vectorConstants struct {
	KeyBytes   int `json:"key_bytes"`
	NonceBytes int `json:"nonce_bytes"`
	TagBytes   int `json:"tag_bytes"`
	RhoBytes   int `json:"rho_bytes"`
	ChunkBytes int `json:"chunk_bytes"`
}

func TestVectors(t *testing.T) {
	for _, v := range loadVectors(t) {
		t.Run(v.Name, func(t *testing.T) {
			key := decodeHex(t, "key", v.KeyHex)
			nonce := decodeHex(t, "nonce", v.NonceHex)
			ad := decodeHex(t, "ad", v.ADHex)
			pt := decodeHex(t, "plaintext", v.PlaintextHex)
			expectedCT := decodeHex(t, "ciphertext", v.CiphertextHex)
			expectedTag := decodeHex(t, "tag", v.TagHex)

			ct, tag := encrypt(key, nonce, ad, pt)

			if !bytes.Equal(tag[:], expectedTag) {
				t.Fatalf("tag mismatch:\n  got  %x\n  want %x", tag[:], expectedTag)
			}

			if !bytes.Equal(ct, expectedCT) {
				t.Fatalf("ciphertext mismatch at byte %d", firstMismatch(ct, expectedCT))
			}

			var etag [TagSize]byte
			copy(etag[:], expectedTag)
			pt2, err := decrypt(key, nonce, ad, ct, etag)
			if err != nil {
				t.Fatalf("Open rejected the reference ciphertext: %v", err)
			}
			if !bytes.Equal(pt2, pt) {
				t.Fatal("round-trip plaintext mismatch")
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

	path := filepath.Join(filepath.Dir(file), "..", "tw128_tv.json")
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
	if vf.Constants.KeyBytes != KeySize ||
		vf.Constants.NonceBytes != NonceSize ||
		vf.Constants.TagBytes != TagSize ||
		vf.Constants.RhoBytes != rhoBytes ||
		vf.Constants.ChunkBytes != ChunkSize {
		t.Fatalf("vector constants do not match Go constants")
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
		{fmt.Sprintf("%d bytes (4 chunks)", ChunkSize*4), ChunkSize * 4},
		{fmt.Sprintf("%d bytes (5 chunks)", ChunkSize*5), ChunkSize * 5},
		{fmt.Sprintf("%d bytes (6 chunks)", ChunkSize*6), ChunkSize * 6},
		{fmt.Sprintf("%d bytes (7 chunks)", ChunkSize*7), ChunkSize * 7},
		{fmt.Sprintf("%d bytes (8 chunks)", ChunkSize*8), ChunkSize * 8},
		{fmt.Sprintf("%d bytes (9 chunks)", ChunkSize*9), ChunkSize * 9},
		{fmt.Sprintf("%d bytes", ChunkSize*11+7), ChunkSize*11 + 7},
	}

	for _, sz := range sizes {
		t.Run(sz.name, func(t *testing.T) {
			pt := seq(sz.size)
			ad := seq(sz.size % 41)

			ct, tag := encrypt(key, nonce, ad, pt)

			if len(ct) != len(pt) {
				t.Fatalf("ciphertext length: got %d, want %d", len(ct), len(pt))
			}

			pt2, err := decrypt(key, nonce, ad, ct, tag)
			if err != nil {
				t.Fatalf("Open failed at size %d: %v", sz.size, err)
			}
			if !bytes.Equal(pt2, pt) {
				t.Fatalf("plaintext mismatch at size %d", sz.size)
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

	if _, err := decrypt(key, nonce, ad, ct, tag); err != nil {
		t.Fatalf("Open rejected the correct AD: %v", err)
	}
	if _, err := decrypt(key, nonce, []byte("wrong"), ct, tag); err == nil {
		t.Fatal("Open accepted the wrong AD")
	}
}

func TestTamperedCiphertext(t *testing.T) {
	key := seq(KeySize)
	nonce := seq(NonceSize)
	pt := seq(1000)

	ct, tag := encrypt(key, nonce, nil, pt)

	if _, err := decrypt(key, nonce, nil, ct, tag); err != nil {
		t.Fatalf("Open rejected the untampered ciphertext: %v", err)
	}

	tampered := make([]byte, len(ct))
	copy(tampered, ct)
	tampered[0] ^= 1
	if _, err := decrypt(key, nonce, nil, tampered, tag); err == nil {
		t.Fatal("Open accepted a tampered ciphertext")
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

func BenchmarkSeal(b *testing.B) {
	key := seq(KeySize)
	nonce := make([]byte, NonceSize)
	a, err := New(key)
	if err != nil {
		b.Fatal(err)
	}
	for _, size := range Sizes {
		pt := make([]byte, size.N)
		ct := make([]byte, 0, size.N+TagSize)
		b.Run(size.Name, func(b *testing.B) {
			b.SetBytes(int64(size.N))
			b.ReportAllocs()
			for b.Loop() {
				ct = a.Seal(ct[:0], nonce, pt, nil)
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

func BenchmarkOpen(b *testing.B) {
	key := seq(KeySize)
	nonce := make([]byte, NonceSize)
	a, err := New(key)
	if err != nil {
		b.Fatal(err)
	}
	for _, size := range Sizes {
		pt := make([]byte, size.N)
		// Allocate out before sealed: sealed's odd size (size.N + TagSize)
		// would otherwise shift out off 2 MiB alignment and cost it
		// transparent-hugepage backing on Linux, slowing the measured
		// streaming stores by up to a third at 16 MiB.
		out := make([]byte, 0, size.N)
		sealed := a.Seal(nil, nonce, pt, nil)
		b.Run(size.Name, func(b *testing.B) {
			b.SetBytes(int64(size.N))
			b.ReportAllocs()
			for b.Loop() {
				var err error
				out, err = a.Open(out[:0], nonce, sealed, nil)
				if err != nil {
					b.Fatal(err)
				}
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
