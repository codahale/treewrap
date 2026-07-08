//go:build arm64 && !purego

package tw128

// The hybrid scalar/NEON kernels process five complete leaf chunks per call:
// four on the NEON unit (two sequential 2-wide pair passes) and a fifth on
// the otherwise-idle scalar pipes, woven into the NEON round stream. See
// tw128_chunks_x5_arm64.s.

//go:noescape
func encryptChunks5ARM64(s *state8, d *duplex, src, dst, tags *byte)

//go:noescape
func decryptChunks5ARM64(s *state8, d *duplex, src, dst, tags *byte)

//go:noescape
func p1600x6Lane(a *state8)

// hasLeafBatch5 reports that this platform drains complete leaves in 5-chunk
// hybrid batches before the wider kernels.
const hasLeafBatch5 = true

// initLeafBatch5 initializes the five leaf lanes a 5-chunk hybrid batch
// uses — instances 0..4 with INIT_LAST for indices baseIndex..baseIndex+4 —
// and permutes only the three instance pairs that carry them. Instances 5-7
// are left zero (instance 5 is permuted to garbage alongside instance 4)
// and unread.
func initLeafBatch5(s *state8, key, nonce []byte, baseIndex uint64) {
	for lane := range lanes {
		for inst := range 6 {
			s.a[lane][inst] = 0
		}
	}

	for inst := range 5 {
		prefix := leafInit(key, nonce, baseIndex+uint64(inst))
		loadInitPrefix(s, inst, prefix[:])
		xorByteInWord(&s.a[leafInitLen>>3][inst], leafInitLen, initLast)
		xorByteInWord(&s.a[(rate-1)>>3][inst], rate-1, 0x80)
	}
	p1600x6Lane(s)
	s.pos = 0
}

// processLeafBatch5 processes the five complete leaf chunks at indices
// g.nLeaves+1 .. g.nLeaves+5, absorbs their tags in leaf order, and advances
// the leaf counter. src and dst must each be exactly 5*ChunkSize bytes.
func (g *aggregator) processLeafBatch5(dst, src []byte) {
	var s state8
	initLeafBatch5(&s, g.key[:], g.nonce[:], g.nLeaves+1)

	// The batch init covered indices g.nLeaves+1..+5, so lane 4 already holds
	// the scalar leaf's post-INIT_LAST state; harvest it instead of paying a
	// separate init permute.
	var d duplex
	for lane := range lanes {
		d.a[lane] = s.a[lane][4]
	}

	var tags leafTagBuffer
	if g.decrypt {
		decryptChunks5ARM64(&s, &d, &src[0], &dst[0], &tags[0])
	} else {
		encryptChunks5ARM64(&s, &d, &src[0], &dst[0], &tags[0])
	}
	g.absorbLeafTags(tags[:5*leafTagSize], 5)
}
