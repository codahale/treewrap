package tw128

import (
	"bytes"
	"crypto/cipher"
	"testing"
)

// staticAssert: *aead satisfies cipher.AEAD.
var _ cipher.AEAD = (*aead)(nil)

func TestAEADRoundTrip(t *testing.T) {
	key := seq(KeySize)
	nonce := seq(NonceSize)

	a, err := New(key)
	if err != nil {
		t.Fatal(err)
	}

	if a.NonceSize() != NonceSize {
		t.Fatalf("NonceSize: got %d, want %d", a.NonceSize(), NonceSize)
	}
	if a.Overhead() != TagSize {
		t.Fatalf("Overhead: got %d, want %d", a.Overhead(), TagSize)
	}

	for _, size := range []int{0, 1, 167, 168, ChunkSize - 1, ChunkSize, ChunkSize + 1, ChunkSize*2 + 7} {
		pt := seq(size)
		ad := seq(size % 41)

		ct := a.Seal(nil, nonce, pt, ad)
		if len(ct) != len(pt)+TagSize {
			t.Fatalf("size %d: ciphertext length got %d, want %d", size, len(ct), len(pt)+TagSize)
		}

		got, err := a.Open(nil, nonce, ct, ad)
		if err != nil {
			t.Fatalf("size %d: Open: %v", size, err)
		}
		if !bytes.Equal(got, pt) {
			t.Fatalf("size %d: round-trip plaintext mismatch", size)
		}
	}
}

func TestAEADTampered(t *testing.T) {
	key := seq(KeySize)
	nonce := seq(NonceSize)
	pt := seq(1000)
	ad := []byte("ad")

	a, _ := New(key)
	ct := a.Seal(nil, nonce, pt, ad)

	cases := map[string]func([]byte){
		"flip ciphertext byte": func(b []byte) { b[0] ^= 1 },
		"flip tag byte":        func(b []byte) { b[len(b)-1] ^= 1 },
		"truncate tag":         nil, // handled below
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			tampered := make([]byte, len(ct))
			copy(tampered, ct)
			if mut != nil {
				mut(tampered)
			} else {
				tampered = tampered[:len(ct)-1]
			}
			if _, err := a.Open(nil, nonce, tampered, ad); err == nil {
				t.Fatal("Open accepted tampered ciphertext")
			}
		})
	}

	// Wrong AD must also fail.
	if _, err := a.Open(nil, nonce, ct, []byte("wrong")); err == nil {
		t.Fatal("Open accepted wrong associated data")
	}
}

func TestAEADTooShort(t *testing.T) {
	key := seq(KeySize)
	nonce := seq(NonceSize)
	a, _ := New(key)

	if _, err := a.Open(nil, nonce, make([]byte, TagSize-1), nil); err == nil {
		t.Fatal("Open accepted ciphertext shorter than the tag")
	}
}

func TestAEADInPlace(t *testing.T) {
	key := seq(KeySize)
	nonce := seq(NonceSize)
	a, _ := New(key)

	for _, size := range []int{0, 1, 168, ChunkSize, ChunkSize + 1, ChunkSize * 2} {
		pt := seq(size)
		buf := make([]byte, size, size+TagSize)
		copy(buf, pt)

		ct := a.Seal(buf[:0], nonce, buf, nil)

		got, err := a.Open(ct[:0], nonce, ct, nil)
		if err != nil {
			t.Fatalf("size %d: Open: %v", size, err)
		}
		if !bytes.Equal(got, pt) {
			t.Fatalf("size %d: in-place round-trip mismatch", size)
		}
	}
}

func TestAEADBadKeySize(t *testing.T) {
	if _, err := New(make([]byte, KeySize-1)); err == nil {
		t.Fatal("New accepted a short key")
	}
}

func TestAEADBadNoncePanics(t *testing.T) {
	key := seq(KeySize)
	a, _ := New(key)

	assertPanic(t, "Seal", func() { a.Seal(nil, make([]byte, NonceSize-1), nil, nil) })
	assertPanic(t, "Open", func() { a.Open(nil, make([]byte, NonceSize-1), make([]byte, TagSize), nil) }) //nolint:errcheck // panics before returning
}

func assertPanic(t *testing.T, name string, fn func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Fatalf("%s did not panic", name)
		}
	}()
	fn()
}
