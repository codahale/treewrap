//go:build amd64 && !purego

package tw128

import (
	"unsafe"

	"github.com/codahale/treewrap/tw128/internal/cpuid"
)

// The architecture kernels process only the chunkFullBlocks full rho-blocks of
// each 8192-byte chunk and store the resulting 8-way state back into s. The
// byte-granular final tail block and tag extraction are completed by
// finish{Encrypt,Decrypt}LeafBatch8 in Go, shared with the generic path.

//go:noescape
func encryptChunksBodyAVX2(s *state8, src, dst *byte)

//go:noescape
func decryptChunksBodyAVX2(s *state8, src, dst *byte)

// The transposed AVX-512 kernels (tw128_chunks_transpose_amd64.s) replace the
// per-lane gather/scatter of the plain AVX-512 body with contiguous loads + an
// in-register transpose; they are the AVX-512 steady-state path.
//
//go:noescape
func encryptChunksBodyAVX512T(s *state8, src, dst *byte)

//go:noescape
func decryptChunksBodyAVX512T(s *state8, src, dst *byte)

func encryptLeafBatch8Arch(s *state8, src, dst []byte, tags *[256]byte) bool {
	if cpuid.HasAVX512 {
		encryptChunksBodyAVX512T(s, unsafe.SliceData(src), unsafe.SliceData(dst))
	} else {
		encryptChunksBodyAVX2(s, unsafe.SliceData(src), unsafe.SliceData(dst))
	}
	finishEncryptLeafBatch8(s, src, dst, tags)
	return true
}

func decryptLeafBatch8Arch(s *state8, src, dst []byte, tags *[256]byte) bool {
	if cpuid.HasAVX512 {
		decryptChunksBodyAVX512T(s, unsafe.SliceData(src), unsafe.SliceData(dst))
	} else {
		decryptChunksBodyAVX2(s, unsafe.SliceData(src), unsafe.SliceData(dst))
	}
	finishDecryptLeafBatch8(s, src, dst, tags)
	return true
}
