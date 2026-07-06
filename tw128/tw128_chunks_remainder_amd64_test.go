//go:build amd64 && !purego

package tw128

import (
	"bytes"
	"testing"

	"github.com/codahale/treewrap/tw128/internal/cpuid"
)

// TestEncryptLeafRemainderAVX512 cross-checks the register-resident masked AVX-512
// kernel plus finishEncryptChunksN against the generic 8-wide path for the low n
// instances (leaf indices 1..n), for every supported remainder width n=2..7.
func TestEncryptLeafRemainderAVX512(t *testing.T) {
	if !cpuid.HasAVX512 {
		t.Skip("no AVX-512 on this host")
	}
	key := seq(KeySize)
	nonce := testChunkNonce()

	for n := 2; n <= 7; n++ {
		src := make([]byte, n*chunkSize)
		for i := range src {
			src[i] = byte(i*7 + i>>8 + n)
		}

		// Reference: generic path over 8 chunks; first n hold src.
		ref := make([]byte, 8*chunkSize)
		copy(ref, src)
		var sr state8
		initLeafBatch8(&sr, key, nonce, 1)
		refDst := make([]byte, 8*chunkSize)
		var refTags leafTagBuffer
		encryptLeafBatch8Generic(&sr, ref, refDst, &refTags)

		// Masked kernel path.
		var sq state8
		initLeafBatch8(&sq, key, nonce, 1)
		dst := make([]byte, n*chunkSize)
		var tags leafTagBuffer
		encryptChunksBodyAVX512N(&sq, &src[0], &dst[0], uint64(n))
		finishEncryptChunksN(&sq, src, dst, &tags, n)

		if !bytes.Equal(dst, refDst[:n*chunkSize]) {
			t.Errorf("n=%d: ciphertext mismatch at byte %d", n, firstMismatch(dst, refDst[:n*chunkSize]))
		}
		if !bytes.Equal(tags[:n*32], refTags[:n*32]) {
			t.Errorf("n=%d: leaf tag mismatch vs generic path", n)
		}
	}
}

// TestEncryptLeafRemainderAVX2 cross-checks the dummy-lane x4 AVX2 kernel plus
// finishEncryptChunksN against the generic 8-wide path for the low n instances
// (leaf indices 1..n), for every supported remainder width n=2..7.
func TestEncryptLeafRemainderAVX2(t *testing.T) {
	key := seq(KeySize)
	nonce := testChunkNonce()

	for n := 2; n <= 7; n++ {
		src := make([]byte, n*chunkSize)
		for i := range src {
			src[i] = byte(i*11 + i>>8 + n)
		}

		// Reference: generic path over 8 chunks; first n hold src.
		ref := make([]byte, 8*chunkSize)
		copy(ref, src)
		var sr state8
		initLeafBatch8(&sr, key, nonce, 1)
		refDst := make([]byte, 8*chunkSize)
		var refTags leafTagBuffer
		encryptLeafBatch8Generic(&sr, ref, refDst, &refTags)

		// Dummy-lane kernel path.
		var sq state8
		initLeafBatch8(&sq, key, nonce, 1)
		dst := make([]byte, n*chunkSize)
		var tags leafTagBuffer
		encryptChunksBodyAVX2N(&sq, &src[0], &dst[0], uint64(n))
		finishEncryptChunksN(&sq, src, dst, &tags, n)

		if !bytes.Equal(dst, refDst[:n*chunkSize]) {
			t.Errorf("n=%d: ciphertext mismatch at byte %d", n, firstMismatch(dst, refDst[:n*chunkSize]))
		}
		if !bytes.Equal(tags[:n*32], refTags[:n*32]) {
			t.Errorf("n=%d: leaf tag mismatch vs generic path", n)
		}
	}
}

// TestDecryptLeafRemainderAVX2 is the decrypt counterpart.
func TestDecryptLeafRemainderAVX2(t *testing.T) {
	key := seq(KeySize)
	nonce := testChunkNonce()

	for n := 2; n <= 7; n++ {
		src := make([]byte, n*chunkSize)
		for i := range src {
			src[i] = byte(i*17 + i>>8 + n)
		}

		ref := make([]byte, 8*chunkSize)
		copy(ref, src)
		var sr state8
		initLeafBatch8(&sr, key, nonce, 1)
		refDst := make([]byte, 8*chunkSize)
		var refTags leafTagBuffer
		decryptLeafBatch8Generic(&sr, ref, refDst, &refTags)

		var sq state8
		initLeafBatch8(&sq, key, nonce, 1)
		dst := make([]byte, n*chunkSize)
		var tags leafTagBuffer
		decryptChunksBodyAVX2N(&sq, &src[0], &dst[0], uint64(n))
		finishDecryptChunksN(&sq, src, dst, &tags, n)

		if !bytes.Equal(dst, refDst[:n*chunkSize]) {
			t.Errorf("n=%d: plaintext mismatch at byte %d", n, firstMismatch(dst, refDst[:n*chunkSize]))
		}
		if !bytes.Equal(tags[:n*32], refTags[:n*32]) {
			t.Errorf("n=%d: leaf tag mismatch vs generic path", n)
		}
	}
}

// TestDecryptLeafRemainderAVX512 is the decrypt counterpart.
func TestDecryptLeafRemainderAVX512(t *testing.T) {
	if !cpuid.HasAVX512 {
		t.Skip("no AVX-512 on this host")
	}
	key := seq(KeySize)
	nonce := testChunkNonce()

	for n := 2; n <= 7; n++ {
		src := make([]byte, n*chunkSize)
		for i := range src {
			src[i] = byte(i*13 + i>>8 + n)
		}

		ref := make([]byte, 8*chunkSize)
		copy(ref, src)
		var sr state8
		initLeafBatch8(&sr, key, nonce, 1)
		refDst := make([]byte, 8*chunkSize)
		var refTags leafTagBuffer
		decryptLeafBatch8Generic(&sr, ref, refDst, &refTags)

		var sq state8
		initLeafBatch8(&sq, key, nonce, 1)
		dst := make([]byte, n*chunkSize)
		var tags leafTagBuffer
		decryptChunksBodyAVX512N(&sq, &src[0], &dst[0], uint64(n))
		finishDecryptChunksN(&sq, src, dst, &tags, n)

		if !bytes.Equal(dst, refDst[:n*chunkSize]) {
			t.Errorf("n=%d: plaintext mismatch at byte %d", n, firstMismatch(dst, refDst[:n*chunkSize]))
		}
		if !bytes.Equal(tags[:n*32], refTags[:n*32]) {
			t.Errorf("n=%d: leaf tag mismatch vs generic path", n)
		}
	}
}
