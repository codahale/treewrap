package tw128

import (
	"crypto/cipher"
	"crypto/subtle"
	"errors"
	"unsafe"
)

// errOpen is the error returned by Open when authentication fails. It is
// deliberately opaque so it does not reveal why verification failed.
var errOpen = errors.New("tw128: message authentication failed")

// aead is a cipher.AEAD implementation backed by TW128. The ciphertext returned
// by Seal is the TW128 encryption of the plaintext with the TagSize-byte
// authentication tag appended.
type aead struct {
	key [KeySize]byte
}

// New returns a cipher.AEAD that encrypts and authenticates using TW128 with the
// given key. The key must be KeySize bytes long.
//
// The returned AEAD uses NonceSize-byte nonces and appends a TagSize-byte tag to
// each ciphertext. Seal and Open panic if the nonce is not NonceSize bytes long.
func New(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, errors.New("tw128: invalid key size")
	}
	a := &aead{}
	copy(a.key[:], key)
	return a, nil
}

// NonceSize returns the size of the nonce that must be passed to Seal and Open.
func (a *aead) NonceSize() int { return NonceSize }

// Overhead returns the maximum difference between the lengths of a plaintext and
// its ciphertext, i.e. the size of the appended authentication tag.
func (a *aead) Overhead() int { return TagSize }

// Seal encrypts and authenticates plaintext, authenticates the additional data,
// and appends the result to dst, returning the updated slice. The nonce must be
// NonceSize bytes long and should be unique for all messages encrypted under the
// same key.
//
// To reuse plaintext's storage for the encrypted output, use plaintext[:0] as
// dst. plaintext and dst must overlap entirely or not at all.
func (a *aead) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != NonceSize {
		panic("tw128: invalid nonce size")
	}

	ret, out := sliceForAppend(dst, len(plaintext)+TagSize)
	if inexactOverlap(out[:len(plaintext)], plaintext) {
		panic("tw128: invalid buffer overlap")
	}

	e := NewEncryptor(a.key[:], nonce, additionalData)
	e.XORKeyStream(out[:len(plaintext)], plaintext)
	tag := e.Finalize()
	copy(out[len(plaintext):], tag[:])

	return ret
}

// Open decrypts and authenticates ciphertext, authenticates the additional data,
// and, if successful, appends the resulting plaintext to dst, returning the
// updated slice. The nonce must be NonceSize bytes long and both it and the
// additional data must match the values passed to Seal.
//
// To reuse ciphertext's storage for the decrypted output, use ciphertext[:0] as
// dst. ciphertext and dst must overlap entirely or not at all. Even if the
// function fails, the contents of dst, up to its capacity, may be overwritten.
func (a *aead) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != NonceSize {
		panic("tw128: invalid nonce size")
	}
	if len(ciphertext) < TagSize {
		return nil, errOpen
	}

	body := ciphertext[:len(ciphertext)-TagSize]
	tag := ciphertext[len(ciphertext)-TagSize:]

	ret, out := sliceForAppend(dst, len(body))
	if inexactOverlap(out, body) {
		panic("tw128: invalid buffer overlap")
	}

	d := NewDecryptor(a.key[:], nonce, additionalData)
	d.XORKeyStream(out, body)
	expected := d.Finalize()

	if subtle.ConstantTimeCompare(expected[:], tag) != 1 {
		// Authentication failed: clear the candidate plaintext so a caller that
		// ignores the error cannot recover it.
		for i := range out {
			out[i] = 0
		}
		return nil, errOpen
	}

	return ret, nil
}

// sliceForAppend extends the input slice by n bytes. head is the full slice with
// length len(in)+n; tail is the appended region. If the capacity of in is large
// enough the storage is reused, otherwise a new slice is allocated.
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}

// inexactOverlap reports whether x and y share memory at any non-corresponding
// index. Buffers that overlap exactly (sharing the same base) are allowed, since
// the underlying XORKeyStream supports fully-overlapping in-place operation.
func inexactOverlap(x, y []byte) bool {
	if len(x) == 0 || len(y) == 0 || &x[0] == &y[0] {
		return false
	}
	return anyOverlap(x, y)
}

// anyOverlap reports whether x and y share any overlapping memory.
func anyOverlap(x, y []byte) bool {
	return len(x) > 0 && len(y) > 0 &&
		uintptr(unsafe.Pointer(&x[0])) <= uintptr(unsafe.Pointer(&y[len(y)-1])) &&
		uintptr(unsafe.Pointer(&y[0])) <= uintptr(unsafe.Pointer(&x[len(x)-1]))
}
