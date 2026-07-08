//go:build amd64 && !purego

package tw128

import "github.com/codahale/treewrap/tw128/internal/cpuid"

// hasWholeMessageTailFusion reports that this platform can fold a ragged
// tail into an n-wide batch as an extra lane.
const hasWholeMessageTailFusion = true

// canFuseTailBatch reports whether a ragged tail of tailLen bytes can ride a
// masked batch alongside nFull full-chunk lanes. The kernel needs AVX-512
// and at least one full MSG_MORE block in the tail; and after the tail lane
// retires, the continuation pass must either have two or more lanes or not
// exist at all (a near-full tail) — an 8-wide pass for a single leftover
// lane loses to the in-register x1 kernel.
func canFuseTailBatch(nFull, tailLen int) bool {
	bodyBlocks := partialBodyBlocks(tailLen)
	if !cpuid.HasAVX512 || bodyBlocks == 0 || nFull < 1 {
		return false
	}
	return nFull >= 2 || bodyBlocks == chunkBodyBlocks
}

// runBatchWithTailLane runs nFull full-chunk lanes plus a tail lane (lane
// nFull, contiguous with them in the message) through the masked body
// kernel: all lanes proceed in lockstep for the tail's full MSG_MORE blocks,
// then the tail lane is extracted and finished byte-granularly in Go while
// the full lanes complete the chunk body (the kernel's further permutes
// scramble the abandoned lane, which is never read again) and their final
// blocks. The full lanes' tags land in tags[:nFull]; the tail leaf's tag is
// returned. s must hold the initialized lane states.
func (g *aggregator) runBatchWithTailLane(s *state8, dst, src []byte, nFull, tailLen int, tags *leafTagBuffer) [leafTagSize]byte {
	bodyBlocks := partialBodyBlocks(tailLen)
	if g.decrypt {
		decryptChunksBodyAVX512N(s, &src[0], &dst[0], uint64(nFull+1), uint64(bodyBlocks))
	} else {
		encryptChunksBodyAVX512N(s, &src[0], &dst[0], uint64(nFull+1), uint64(bodyBlocks))
	}

	// Extract the tail leaf and finish its final partial block.
	var tail duplex
	for lane := range lanes {
		tail.a[lane] = s.a[lane][nFull]
	}
	off := nFull*ChunkSize + bodyBlocks*rhoBytes
	end := nFull*ChunkSize + tailLen
	tail.bodyMore(dst[off:end], src[off:end], g.decrypt, msgMore)
	tail.closeBlock(msgLast)

	// Continue the full lanes for the rest of the chunk body, then finish
	// their final blocks and extract their tags.
	if rem := chunkBodyBlocks - bodyBlocks; rem > 0 {
		boff := bodyBlocks * rhoBytes
		if g.decrypt {
			decryptChunksBodyAVX512N(s, &src[boff], &dst[boff], uint64(nFull), uint64(rem))
		} else {
			encryptChunksBodyAVX512N(s, &src[boff], &dst[boff], uint64(nFull), uint64(rem))
		}
	}
	if g.decrypt {
		finishDecryptChunkLanes(s, src, dst, tags, nFull)
	} else {
		finishEncryptChunkLanes(s, src, dst, tags, nFull)
	}
	return tail.tagBytes()
}

// tryFuseWholeMessageWithTail handles an entire message — chunk 0, nComplete
// complete leaves, and a ragged tail — in one masked n-wide batch. The
// n-wide kernel's cost is nearly flat in the lane count, so folding the tail
// into the batch replaces an entire serial x1 pass with one extra lane.
//
// Lane 0 carries the trunk through its chunk-0 phase (the lane-0 fusion
// contract), lanes 1..k-1 the complete leaves, and lane k the tail leaf.
// g must be at the start of the cascade. It reports whether the fused path
// ran.
func (g *aggregator) tryFuseWholeMessageWithTail(dst, src []byte, nComplete, tailLen int) bool {
	k := 1 + nComplete
	if !canFuseTailBatch(k, tailLen) {
		return false
	}

	var s state8
	initChunk0BatchState(&s, g)
	var tags leafTagBuffer
	ttag := g.runBatchWithTailLane(&s, dst, src, k, tailLen, &tags)

	// Write the trunk back from lane 0, then absorb the leaf tags in leaf
	// order: the complete leaves, then the tail leaf.
	for lane := range lanes {
		g.trunk.a[lane] = s.a[lane][0]
	}
	g.absorbLeafTags(tags[leafTagSize:k*leafTagSize], k-1)
	g.absorbLeafTags(ttag[:], 1)
	return true
}

// fuseLeafRemainderWithTail processes the trailing nComplete (1..7) complete
// leaf chunks and the ragged tail as one masked batch: lanes 0..nComplete-1
// carry the complete leaves at indices g.nLeaves+1.., lane nComplete the
// tail leaf. The caller must have established canFuseTailBatch(tailLen).
func (g *aggregator) fuseLeafRemainderWithTail(dst, src []byte, nComplete, tailLen int) {
	var s state8
	initLeafBatch8(&s, g.key[:], g.nonce[:], g.nLeaves+1)
	var tags leafTagBuffer
	ttag := g.runBatchWithTailLane(&s, dst, src, nComplete, tailLen, &tags)
	g.absorbLeafTags(tags[:nComplete*leafTagSize], nComplete)
	g.absorbLeafTags(ttag[:], 1)
}
