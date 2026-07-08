package tw128

import (
	"bytes"
	"math/rand/v2"
	"testing"
)

// TestBodyBlocksArchVsGeneric checks the in-register x1 body kernel against
// the generic duplex across random states, data, and body lengths, in both
// directions. On platforms without a kernel, bodyBlocksArch consumes zero
// bytes and the test degenerates to comparing bodyMore with itself.
func TestBodyBlocksArchVsGeneric(t *testing.T) {
	rng := rand.New(rand.NewPCG(7, 8))

	for trial := range 100 {
		size := 1 + rng.IntN(ChunkSize)
		decrypt := trial%2 == 1

		var key [KeySize]byte
		var nonce [NonceSize]byte
		fillRandBody(rng, key[:])
		fillRandBody(rng, nonce[:])

		p := leafInit(key[:], nonce[:], uint64(trial))
		var want, got duplex
		want.initWith(p[:])
		got = want

		src := make([]byte, size)
		fillRandBody(rng, src)
		dstWant := make([]byte, size)
		dstGot := make([]byte, size)

		want.bodyMore(dstWant, src, decrypt, msgMore)
		want.closeBlock(msgLast)

		consumed := got.bodyBlocksArch(dstGot, src, decrypt)
		got.bodyMore(dstGot[consumed:], src[consumed:], decrypt, msgMore)
		got.closeBlock(msgLast)

		if got.a != want.a {
			t.Fatalf("trial %d (size %d, decrypt %v): state mismatch", trial, size, decrypt)
		}
		if !bytes.Equal(dstGot, dstWant) {
			t.Fatalf("trial %d (size %d, decrypt %v): output mismatch at byte %d",
				trial, size, decrypt, firstMismatch(dstGot, dstWant))
		}
	}
}

func fillRandBody(rng *rand.Rand, b []byte) {
	for i := range b {
		b[i] = byte(rng.Uint32())
	}
}
