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
		var g aggregator
		copy(g.key[:], key)
		copy(g.nonce[:], nonce)
		encryptChunkPair(&g, src, dst)
		decryptChunkPair(&g, src, dst)
	})

	t.Run("run", func(t *testing.T) {
		for rem := 2; rem <= 7; rem++ {
			n := rem * ChunkSize
			src := guardedTail(t, n)
			dst := guardedTail(t, n)
			copy(src, seq(n))
			var g aggregator
			copy(g.key[:], key)
			copy(g.nonce[:], nonce)
			encryptChunkRun(&g, src, dst, rem)
			decryptChunkRun(&g, src, dst, rem)
		}
	})

	t.Run("fused", func(t *testing.T) {
		for _, k := range []int{2, 8} {
			n := k * ChunkSize
			src := guardedTail(t, n)
			dst := guardedTail(t, n)
			copy(src, seq(n))
			var g aggregator
			copy(g.key[:], key)
			copy(g.nonce[:], nonce)
			encryptChunk0Fused(&g, src, dst, k)
			decryptChunk0Fused(&g, src, dst, k)
		}
	})
}
