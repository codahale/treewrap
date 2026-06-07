//go:build amd64 && !purego

package tw128

import (
	"bytes"
	"testing"

	"github.com/codahale/treewrap/tw128/internal/cpuid"
)

// TestChunksTransposeKernel cross-checks the transposed AVX-512 steady-state
// kernel (body + the shared Go finish) against the generic 8-wide path, for both
// encrypt and decrypt over 8 chunks. The arch dispatch also routes through this
// kernel on AVX-512 hosts, so TestEncryptChunks/TestDecryptChunks and TestVectors
// exercise it too; this is the direct check.
func TestChunksTransposeKernel(t *testing.T) {
	if !cpuid.HasAVX512 {
		t.Skip("no AVX-512 on this host")
	}
	key := seq(KeySize)
	nonce := testChunkNonce()

	src := make([]byte, 8*chunkSize)
	for i := range src {
		src[i] = byte(i*7 + i>>8)
	}

	var sr state8
	initChunks(&sr, key, nonce, 1)
	refDst := make([]byte, 8*chunkSize)
	var refTags [256]byte
	encryptChunksGeneric(&sr, src, refDst, &refTags)

	var st state8
	initChunks(&st, key, nonce, 1)
	dst := make([]byte, 8*chunkSize)
	var tags [256]byte
	encryptChunksBodyAVX512T(&st, &src[0], &dst[0])
	finishEncryptChunks(&st, src, dst, &tags)

	if !bytes.Equal(dst, refDst) {
		t.Errorf("encrypt: ciphertext mismatch at byte %d", firstMismatch(dst, refDst))
	}
	if tags != refTags {
		t.Error("encrypt: leaf-tag mismatch vs generic")
	}

	var dr state8
	initChunks(&dr, key, nonce, 1)
	refPt := make([]byte, 8*chunkSize)
	var refDTags [256]byte
	decryptChunksGeneric(&dr, src, refPt, &refDTags)

	var dt state8
	initChunks(&dt, key, nonce, 1)
	pt := make([]byte, 8*chunkSize)
	var dtags [256]byte
	decryptChunksBodyAVX512T(&dt, &src[0], &pt[0])
	finishDecryptChunks(&dt, src, pt, &dtags)

	if !bytes.Equal(pt, refPt) {
		t.Errorf("decrypt: plaintext mismatch at byte %d", firstMismatch(pt, refPt))
	}
	if dtags != refDTags {
		t.Error("decrypt: leaf-tag mismatch vs generic")
	}
}
