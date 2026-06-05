package tw128

import (
	"bytes"
	"testing"
)

// fuzzMaxLen bounds fuzzed message lengths so a single execution stays cheap
// while still spanning enough chunks to exercise the x8, pad-to-8, and x1
// remainder paths in processComplete (9 leaf chunks plus a ragged tail).
const fuzzMaxLen = 9*ChunkSize + 4096

// fixedSize returns a deterministic n-byte slice derived from seed (repeating
// seed, or zero-filled when seed is empty), letting the fuzzer drive key and
// nonce material of arbitrary length into the fixed sizes the API requires.
func fixedSize(seed []byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		if len(seed) > 0 {
			out[i] = seed[i%len(seed)]
		}
	}
	return out
}

// FuzzRoundTrip checks that decryption recovers the plaintext and that the
// encrypt and decrypt tags agree for arbitrary key, nonce, associated data, and
// message lengths. Varying the length is the point: it walks chunk boundaries,
// ragged tail blocks, and leaf counts that the fixed-size tests only sample.
func FuzzRoundTrip(f *testing.F) {
	f.Add([]byte("key"), []byte("nonce"), []byte("ad"), []byte("plaintext"))
	f.Add([]byte{}, []byte{}, []byte{}, []byte{})
	f.Add(seq(KeySize), seq(NonceSize), seq(40), seq(rhoBytes))
	f.Add(seq(KeySize), seq(NonceSize), []byte(nil), seq(ChunkSize))
	f.Add(seq(KeySize), seq(NonceSize), seq(7), seq(ChunkSize*3+999))
	f.Fuzz(func(t *testing.T, keySeed, nonceSeed, ad, pt []byte) {
		if len(pt) > fuzzMaxLen {
			pt = pt[:fuzzMaxLen]
		}
		key := fixedSize(keySeed, KeySize)
		nonce := fixedSize(nonceSeed, NonceSize)

		ct, tag := encrypt(key, nonce, ad, pt)
		if len(ct) != len(pt) {
			t.Fatalf("ciphertext length: got %d, want %d", len(ct), len(pt))
		}

		pt2, tag2 := decrypt(key, nonce, ad, ct)
		if !bytes.Equal(pt2, pt) {
			t.Fatalf("round-trip plaintext mismatch (len=%d)", len(pt))
		}
		if tag != tag2 {
			t.Fatalf("round-trip tag mismatch (len=%d)", len(pt))
		}
	})
}

// FuzzIncremental checks that splitting a message into arbitrary XORKeyStream
// writes produces byte-identical ciphertext and tag to a single-call encrypt.
// The split points are fuzzed, so this exercises the streaming state machine:
// partial-leaf continuation, the chunk-0 to leaf-mode transition, and the
// processComplete remainder paths at boundaries the fixed tests do not reach.
func FuzzIncremental(f *testing.F) {
	f.Add(seq(KeySize), seq(NonceSize), []byte("ad"), seq(ChunkSize*2+500), []byte{1, 7, 168, 169})
	f.Add(seq(KeySize), seq(NonceSize), []byte{}, seq(ChunkSize+1), []byte{255})
	f.Add(seq(KeySize), seq(NonceSize), seq(13), seq(ChunkSize*5+3), []byte{200, 1, 50})
	f.Fuzz(func(t *testing.T, keySeed, nonceSeed, ad, pt, splits []byte) {
		if len(pt) > fuzzMaxLen {
			pt = pt[:fuzzMaxLen]
		}
		key := fixedSize(keySeed, KeySize)
		nonce := fixedSize(nonceSeed, NonceSize)

		refCT, refTag := encrypt(key, nonce, ad, pt)

		ct := make([]byte, len(pt))
		e := NewEncryptor(key, nonce, ad)
		for off, si := 0, 0; off < len(pt); {
			n := len(pt) - off
			if len(splits) > 0 {
				n = min(int(splits[si%len(splits)])+1, len(pt)-off)
				si++
			}
			e.XORKeyStream(ct[off:off+n], pt[off:off+n])
			off += n
		}
		tag := e.Finalize()

		if !bytes.Equal(ct, refCT) {
			t.Fatalf("incremental ciphertext mismatch (len=%d)", len(pt))
		}
		if tag != refTag {
			t.Fatalf("incremental tag mismatch (len=%d)", len(pt))
		}
	})
}

// FuzzChunksGenericVsArch checks that the architecture-dispatched 8-way chunk
// kernels (AVX-512/AVX2 on amd64, NEON on arm64) agree byte-for-byte with the
// pure-Go reference on both ciphertext/plaintext and the extracted leaf tags,
// for arbitrary chunk contents and base leaf index. On purego or unsupported
// architectures both sides resolve to the generic path and the check is
// trivially satisfied; the value lands on the vectorized backends.
func FuzzChunksGenericVsArch(f *testing.F) {
	f.Add(seq(64), uint64(1))
	f.Add(seq(8*ChunkSize), uint64(0))
	f.Add([]byte{0xff}, ^uint64(0)) // baseIndex near wraparound
	f.Fuzz(func(t *testing.T, srcSeed []byte, baseIndex uint64) {
		key := seq(KeySize)
		nonce := testChunkNonce()
		src := fixedSize(srcSeed, 8*ChunkSize)

		// Encrypt: generic reference vs arch dispatch.
		var sgen state8
		initChunks(&sgen, key, nonce, baseIndex)
		genDst := make([]byte, 8*ChunkSize)
		var genTags [256]byte
		encryptChunksGeneric(&sgen, src, genDst, &genTags)

		archDst := make([]byte, 8*ChunkSize)
		var archTags [256]byte
		encryptChunks(key, nonce, baseIndex, src, archDst, &archTags)

		if !bytes.Equal(genDst, archDst) {
			t.Fatalf("encrypt ciphertext mismatch (baseIndex=%d)", baseIndex)
		}
		if genTags != archTags {
			t.Fatalf("encrypt tag mismatch (baseIndex=%d)", baseIndex)
		}

		// Decrypt: treat the same bytes as ciphertext.
		var sgen2 state8
		initChunks(&sgen2, key, nonce, baseIndex)
		genPt := make([]byte, 8*ChunkSize)
		var genTags2 [256]byte
		decryptChunksGeneric(&sgen2, src, genPt, &genTags2)

		archPt := make([]byte, 8*ChunkSize)
		var archTags2 [256]byte
		decryptChunks(key, nonce, baseIndex, src, archPt, &archTags2)

		if !bytes.Equal(genPt, archPt) {
			t.Fatalf("decrypt plaintext mismatch (baseIndex=%d)", baseIndex)
		}
		if genTags2 != archTags2 {
			t.Fatalf("decrypt tag mismatch (baseIndex=%d)", baseIndex)
		}
	})
}
