//go:build amd64 && !purego

package tw128

import (
	"unsafe"

	"github.com/codahale/treewrap/tw128/internal/cpuid"
)

// The architecture kernels process only the chunkFullBlocks full rho-blocks of
// each 8192-byte chunk and store the resulting 8-way state back into s. The
// byte-granular final tail block and tag extraction are completed by
// finish{Encrypt,Decrypt}Chunks in Go, shared with the generic path.

//go:noescape
func encryptChunksBodyAVX512(s *state8, src, dst *byte)

//go:noescape
func encryptChunksBodyAVX2(s *state8, src, dst *byte)

//go:noescape
func decryptChunksBodyAVX512(s *state8, src, dst *byte)

//go:noescape
func decryptChunksBodyAVX2(s *state8, src, dst *byte)

func encryptChunksArch(s *state8, src, dst []byte, tags *[256]byte) bool {
	if cpuid.HasAVX512 {
		encryptChunksBodyAVX512(s, unsafe.SliceData(src), unsafe.SliceData(dst))
	} else {
		encryptChunksBodyAVX2(s, unsafe.SliceData(src), unsafe.SliceData(dst))
	}
	finishEncryptChunks(s, src, dst, tags)
	return true
}

func decryptChunksArch(s *state8, src, dst []byte, tags *[256]byte) bool {
	if cpuid.HasAVX512 {
		decryptChunksBodyAVX512(s, unsafe.SliceData(src), unsafe.SliceData(dst))
	} else {
		decryptChunksBodyAVX2(s, unsafe.SliceData(src), unsafe.SliceData(dst))
	}
	finishDecryptChunks(s, src, dst, tags)
	return true
}
