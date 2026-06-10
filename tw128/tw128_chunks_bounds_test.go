//go:build unix

package tw128

import (
	"syscall"
	"testing"
)

// guardedTail returns a slice of n bytes whose final byte abuts an unmapped
// guard page, so any access past the slice faults instead of silently reading
// or clobbering adjacent memory.
func guardedTail(t *testing.T, n int) []byte {
	t.Helper()
	page := syscall.Getpagesize()
	total := ((n+page-1)/page + 1) * page
	mem, err := syscall.Mmap(-1, 0, total, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_ANON|syscall.MAP_PRIVATE)
	if err != nil {
		t.Fatalf("mmap: %v", err)
	}
	t.Cleanup(func() {
		if err := syscall.Munmap(mem); err != nil {
			t.Fatalf("munmap: %v", err)
		}
	})
	if err := syscall.Mprotect(mem[total-page:], syscall.PROT_NONE); err != nil {
		t.Fatalf("mprotect: %v", err)
	}
	return mem[total-page-n : total-page]
}

// TestChunkKernelsStayInBounds runs the fused chunk kernels with src and dst
// ending flush against an unmapped page, so a kernel that touches any byte
// past the chunks it was given faults the test process.
func TestChunkKernelsStayInBounds(t *testing.T) {
	key := seq(KeySize)
	nonce := seq(NonceSize)

	t.Run("x8", func(t *testing.T) {
		const n = 8 * ChunkSize
		src := guardedTail(t, n)
		dst := guardedTail(t, n)
		copy(src, seq(n))
		var tags [256]byte
		encryptChunks(key, nonce, 1, src, dst, &tags)
		decryptChunks(key, nonce, 1, src, dst, &tags)
	})

	t.Run("pair", func(t *testing.T) {
		const n = 2 * ChunkSize
		src := guardedTail(t, n)
		dst := guardedTail(t, n)
		copy(src, seq(n))
		var c cryptor
		copy(c.key[:], key)
		copy(c.nonce[:], nonce)
		encryptChunkPair(&c, src, dst)
		decryptChunkPair(&c, src, dst)
	})
}
