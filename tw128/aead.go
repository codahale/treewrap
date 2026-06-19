package tw128

import (
	"crypto/subtle"
	"errors"
	"unsafe"
)

// errOpen is the error returned by Open when authentication fails. It is
// deliberately opaque so it does not reveal why verification failed.
var errOpen = errors.New("tw128: message authentication failed")

// AEAD is a cipher.AEAD implementation backed by TW128. The ciphertext returned
// by Seal is the TW128 encryption of the plaintext with the TagSize-byte
// authentication tag appended.
type AEAD struct {
	key [KeySize]byte
}

// New returns a cipher.AEAD that encrypts and authenticates using TW128 with the
// given key. The key must be KeySize bytes long.
//
// The returned AEAD uses NonceSize-byte nonces and appends a TagSize-byte tag to
// each ciphertext. Seal and Open panic if the nonce is not NonceSize bytes long.
func New(key []byte) (*AEAD, error) {
	if len(key) != KeySize {
		return nil, errors.New("tw128: invalid key size")
	}
	a := &AEAD{}
	copy(a.key[:], key)
	return a, nil
}

// NonceSize returns the size of the nonce that must be passed to Seal and Open.
func (a *AEAD) NonceSize() int { return NonceSize }

// Overhead returns the maximum difference between the lengths of a plaintext and
// its ciphertext, i.e. the size of the appended authentication tag.
func (a *AEAD) Overhead() int { return TagSize }

// EncryptAndHash encrypts and authenticates plaintext, authenticates the
// additional data, and appends the encrypted output to dst, returning the
// updated slice and the TagSize-byte authentication tag. Unlike Seal, the tag is
// returned separately rather than appended to the ciphertext. The nonce must be
// NonceSize bytes long and should be unique for all messages encrypted under the
// same key.
//
// To reuse plaintext's storage for the encrypted output, use plaintext[:0] as
// dst. plaintext and dst must overlap entirely or not at all.
func (a *AEAD) EncryptAndHash(dst, nonce, plaintext, additionalData []byte) ([]byte, [32]byte) {
	if len(nonce) != NonceSize {
		panic("tw128: invalid nonce size")
	}

	ret, out := sliceForAppend(dst, len(plaintext))
	if inexactOverlap(out[:len(plaintext)], plaintext) {
		panic("tw128: invalid buffer overlap")
	}

	tag := crypt(a.key[:], nonce, additionalData, out, plaintext, false)

	return ret, tag
}

// DecryptAndHash decrypts ciphertext, authenticates the additional data, appends
// the resulting plaintext to dst, and returns the updated slice together with the
// TagSize-byte authentication tag recomputed over the inputs. Unlike Open, it
// does not verify the tag: the caller must compare the returned tag against the
// expected value in constant time (e.g. with crypto/subtle) and discard the
// plaintext if they differ. The nonce must be NonceSize bytes long and must match
// the value passed to EncryptAndHash.
//
// To reuse ciphertext's storage for the decrypted output, use ciphertext[:0] as
// dst. ciphertext and dst must overlap entirely or not at all.
func (a *AEAD) DecryptAndHash(dst, nonce, ciphertext, additionalData []byte) ([]byte, [32]byte) {
	if len(nonce) != NonceSize {
		panic("tw128: invalid nonce size")
	}

	ret, out := sliceForAppend(dst, len(ciphertext))
	if inexactOverlap(out[:len(ciphertext)], ciphertext) {
		panic("tw128: invalid buffer overlap")
	}

	tag := crypt(a.key[:], nonce, additionalData, out, ciphertext, true)

	return ret, tag
}

// Seal encrypts and authenticates plaintext, authenticates the additional data,
// and appends the result to dst, returning the updated slice. The nonce must be
// NonceSize bytes long and should be unique for all messages encrypted under the
// same key.
//
// To reuse plaintext's storage for the encrypted output, use plaintext[:0] as
// dst. plaintext and dst must overlap entirely or not at all.
func (a *AEAD) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	ret, tag := a.EncryptAndHash(dst, nonce, plaintext, additionalData)
	return append(ret, tag[:]...)
}

// Open decrypts and authenticates ciphertext, authenticates the additional data,
// and, if successful, appends the resulting plaintext to dst, returning the
// updated slice. The nonce must be NonceSize bytes long and both it and the
// additional data must match the values passed to Seal.
//
// To reuse ciphertext's storage for the decrypted output, use ciphertext[:0] as
// dst. ciphertext and dst must overlap entirely or not at all. Even if the
// function fails, the contents of dst, up to its capacity, may be overwritten.
func (a *AEAD) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != NonceSize {
		panic("tw128: invalid nonce size")
	}
	if len(ciphertext) < TagSize {
		return nil, errOpen
	}

	body := ciphertext[:len(ciphertext)-TagSize]
	tag := ciphertext[len(ciphertext)-TagSize:]

	ret, expected := a.DecryptAndHash(dst, nonce, body, additionalData)

	if subtle.ConstantTimeCompare(expected[:], tag) != 1 {
		// Authentication failed: clear the candidate plaintext so a caller that
		// ignores the error cannot recover it.
		out := ret[len(ret)-len(body):]
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
// the underlying pipeline supports fully-overlapping in-place operation.
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
