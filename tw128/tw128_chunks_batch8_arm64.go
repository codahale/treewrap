//go:build arm64 && !purego

package tw128

import "unsafe"

//go:noescape
func encryptChunksARM64(s *state8, src, dst *byte, cvs *byte)

//go:noescape
func decryptChunksARM64(s *state8, src, dst *byte, cvs *byte)

func encryptLeafBatch8Arch(s *state8, src, dst []byte, tags *leafTagBuffer) bool {
	encryptChunksARM64(s, unsafe.SliceData(src), unsafe.SliceData(dst), &tags[0])
	return true
}

func decryptLeafBatch8Arch(s *state8, src, dst []byte, tags *leafTagBuffer) bool {
	decryptChunksARM64(s, unsafe.SliceData(src), unsafe.SliceData(dst), &tags[0])
	return true
}
