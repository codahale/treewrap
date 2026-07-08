//go:build amd64 && !purego

package tw128

import "github.com/codahale/treewrap/tw128/internal/cpuid"

// hasWholeMessageTailFusion reports that this platform can process chunk 0,
// the complete leaves, and a ragged tail in a single n-wide batch.
const hasWholeMessageTailFusion = true

// tryFuseWholeMessageWithTail handles an entire message — chunk 0, nComplete
// complete leaves, and a ragged tail — in one masked n-wide batch. The
// n-wide kernel's cost is nearly flat in the lane count, so folding the tail
// into the batch replaces an entire serial x1 pass with one extra lane.
//
// Lane 0 carries the trunk through its chunk-0 phase (the lane-0 fusion
// contract), lanes 1..k-1 the complete leaves, and lane k the tail leaf. All
// lanes run in lockstep for the tail's full MSG_MORE blocks; the tail lane
// is then extracted and finished byte-granularly in Go while the full lanes
// continue (the kernel's permutes scramble the abandoned lane, which is
// never read again). g must be at the start of the cascade. It reports
// whether the fused path ran.
func (g *aggregator) tryFuseWholeMessageWithTail(dst, src []byte, nComplete, tailLen int) bool {
	if !cpuid.HasAVX512 {
		return false
	}
	bodyBlocks := partialBodyBlocks(tailLen)
	if bodyBlocks == 0 {
		return false
	}
	k := 1 + nComplete

	var s state8
	initChunk0BatchState(&s, g)
	if g.decrypt {
		decryptChunksBodyAVX512N(&s, &src[0], &dst[0], uint64(k+1), uint64(bodyBlocks))
	} else {
		encryptChunksBodyAVX512N(&s, &src[0], &dst[0], uint64(k+1), uint64(bodyBlocks))
	}

	// Extract the tail leaf (lane k) and finish its final partial block.
	var tail duplex
	for lane := range lanes {
		tail.a[lane] = s.a[lane][k]
	}
	off := k*ChunkSize + bodyBlocks*rhoBytes
	end := k*ChunkSize + tailLen
	tail.bodyMore(dst[off:end], src[off:end], g.decrypt, msgMore)
	tail.closeBlock(msgLast)

	// Continue the full lanes for the rest of the chunk body, then finish
	// their final blocks and extract their tags.
	if rem := chunkBodyBlocks - bodyBlocks; rem > 0 {
		boff := bodyBlocks * rhoBytes
		if g.decrypt {
			decryptChunksBodyAVX512N(&s, &src[boff], &dst[boff], uint64(k), uint64(rem))
		} else {
			encryptChunksBodyAVX512N(&s, &src[boff], &dst[boff], uint64(k), uint64(rem))
		}
	}
	var tags leafTagBuffer
	if g.decrypt {
		finishDecryptChunkLanes(&s, src, dst, &tags, k)
	} else {
		finishEncryptChunkLanes(&s, src, dst, &tags, k)
	}

	// Write the trunk back from lane 0, then absorb the leaf tags in leaf
	// order: the complete leaves, then the tail leaf.
	for lane := range lanes {
		g.trunk.a[lane] = s.a[lane][0]
	}
	g.absorbLeafTags(tags[leafTagSize:k*leafTagSize], k-1)
	ttag := tail.tagBytes()
	g.absorbLeafTags(ttag[:], 1)
	return true
}
