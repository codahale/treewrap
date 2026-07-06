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
	initLeafBatch8(&sr, key, nonce, 1)
	refDst := make([]byte, 8*chunkSize)
	var refTags leafTagBuffer
	encryptLeafBatch8Generic(&sr, src, refDst, &refTags)

	var st state8
	initLeafBatch8(&st, key, nonce, 1)
	dst := make([]byte, 8*chunkSize)
	var tags leafTagBuffer
	encryptChunksBodyAVX512T(&st, &src[0], &dst[0])
	finishEncryptLeafBatch8(&st, src, dst, &tags)

	if !bytes.Equal(dst, refDst) {
		t.Errorf("encrypt: ciphertext mismatch at byte %d", firstMismatch(dst, refDst))
	}
	if tags != refTags {
		t.Error("encrypt: leaf tag mismatch vs generic")
	}

	var dr state8
	initLeafBatch8(&dr, key, nonce, 1)
	refPt := make([]byte, 8*chunkSize)
	var refDTags leafTagBuffer
	decryptLeafBatch8Generic(&dr, src, refPt, &refDTags)

	var dt state8
	initLeafBatch8(&dt, key, nonce, 1)
	pt := make([]byte, 8*chunkSize)
	var dtags leafTagBuffer
	decryptChunksBodyAVX512T(&dt, &src[0], &pt[0])
	finishDecryptLeafBatch8(&dt, src, pt, &dtags)

	if !bytes.Equal(pt, refPt) {
		t.Errorf("decrypt: plaintext mismatch at byte %d", firstMismatch(pt, refPt))
	}
	if dtags != refDTags {
		t.Error("decrypt: leaf tag mismatch vs generic")
	}
}
