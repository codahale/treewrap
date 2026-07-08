//go:build arm64 && !purego

package tw128

import (
	"bytes"
	"math/rand/v2"
	"testing"
)

// TestChunks5VsSerialLeaves checks the hybrid x5 kernel (both directions)
// against five leaves processed serially through the generic duplex.
func TestChunks5VsSerialLeaves(t *testing.T) {
	rng := rand.New(rand.NewPCG(3, 4))
	key := make([]byte, KeySize)
	nonce := make([]byte, NonceSize)
	fillRand(rng, key)
	fillRand(rng, nonce)

	src := make([]byte, 5*ChunkSize)
	fillRand(rng, src)

	const base = uint64(1)
	wantDst := make([]byte, 5*ChunkSize)
	var wantTags [5 * leafTagSize]byte
	for i := range 5 {
		var leaf duplex
		off := i * ChunkSize
		encryptX1(key, nonce, base+uint64(i), src[off:off+ChunkSize], wantDst[off:off+ChunkSize], &leaf)
		tag := leaf.tagBytes()
		copy(wantTags[i*leafTagSize:], tag[:])
	}

	var s state8
	initLeafBatch8(&s, key, nonce, base)
	var d duplex
	p := leafInit(key, nonce, base+4)
	d.initWith(p[:])
	gotDst := make([]byte, 5*ChunkSize)
	var tags leafTagBuffer
	encryptChunks5ARM64(&s, &d, &src[0], &gotDst[0], &tags[0])

	if !bytes.Equal(gotDst, wantDst) {
		t.Fatalf("encrypt ciphertext mismatch at byte %d", firstMismatch(gotDst, wantDst))
	}
	if !bytes.Equal(tags[:5*leafTagSize], wantTags[:]) {
		t.Fatalf("encrypt tag mismatch at byte %d", firstMismatch(tags[:5*leafTagSize], wantTags[:]))
	}

	// Decrypt the ciphertext back and compare plaintext and tags.
	initLeafBatch8(&s, key, nonce, base)
	d.initWith(p[:])
	gotPt := make([]byte, 5*ChunkSize)
	var dtags leafTagBuffer
	decryptChunks5ARM64(&s, &d, &wantDst[0], &gotPt[0], &dtags[0])

	if !bytes.Equal(gotPt, src) {
		t.Fatalf("decrypt plaintext mismatch at byte %d", firstMismatch(gotPt, src))
	}
	if !bytes.Equal(dtags[:5*leafTagSize], wantTags[:]) {
		t.Fatalf("decrypt tag mismatch at byte %d", firstMismatch(dtags[:5*leafTagSize], wantTags[:]))
	}
}

func fillRand(rng *rand.Rand, b []byte) {
	for i := range b {
		b[i] = byte(rng.Uint32())
	}
}

// BenchmarkChunks5Kernel and BenchmarkChunks8Kernel compare the hybrid
// 5-chunk kernel against the 8-wide NEON batch, inits included.
func BenchmarkChunks5Kernel(b *testing.B) {
	key := seq(KeySize)
	nonce := seq(NonceSize)
	src := make([]byte, 5*ChunkSize)
	dst := make([]byte, 5*ChunkSize)
	var tags leafTagBuffer
	b.SetBytes(5 * ChunkSize)
	for b.Loop() {
		var s state8
		initLeafBatch5(&s, key, nonce, 1)
		var d duplex
		for lane := range lanes {
			d.a[lane] = s.a[lane][4]
		}
		encryptChunks5ARM64(&s, &d, &src[0], &dst[0], &tags[0])
	}
}

func BenchmarkChunks8Kernel(b *testing.B) {
	key := seq(KeySize)
	nonce := seq(NonceSize)
	src := make([]byte, 8*ChunkSize)
	dst := make([]byte, 8*ChunkSize)
	var tags leafTagBuffer
	b.SetBytes(8 * ChunkSize)
	for b.Loop() {
		encryptLeafBatch8(key, nonce, 1, src, dst, &tags)
	}
}
