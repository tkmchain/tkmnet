package tkmnet

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	chunkMagic       = "TKCH"
	chunkHeaderSize  = 4 + 1 + 16 + 4 + 4 + 2
	MaxChunkData     = MaxPayload - chunkHeaderSize
	MaxTransferBytes = 16 * 1024 * 1024
)

// Chunk is the fixed-size transfer unit for large shielded transactions and
// other service payloads. A transaction can be up to the block-size limit
// without making an individual onion packet variable-sized.
type Chunk struct {
	TransferID [CircuitIDSize]byte
	Index      uint32
	Count      uint32
	Data       []byte
}

func EncodeChunk(chunk Chunk) ([]byte, error) {
	if chunk.Count == 0 || chunk.Index >= chunk.Count || len(chunk.Data) > MaxChunkData {
		return nil, errors.New("tkmnet: invalid transfer chunk")
	}
	encoded := make([]byte, MaxPayload)
	copy(encoded[:4], chunkMagic)
	encoded[4] = Version
	copy(encoded[5:21], chunk.TransferID[:])
	binary.BigEndian.PutUint32(encoded[21:25], chunk.Index)
	binary.BigEndian.PutUint32(encoded[25:29], chunk.Count)
	binary.BigEndian.PutUint16(encoded[29:31], uint16(len(chunk.Data)))
	copy(encoded[31:], chunk.Data)
	return encoded, nil
}

func DecodeChunk(encoded []byte) (Chunk, error) {
	var chunk Chunk
	if len(encoded) != MaxPayload || !bytes.Equal(encoded[:4], []byte(chunkMagic)) || encoded[4] != Version {
		return chunk, errors.New("tkmnet: invalid transfer chunk")
	}
	copy(chunk.TransferID[:], encoded[5:21])
	chunk.Index = binary.BigEndian.Uint32(encoded[21:25])
	chunk.Count = binary.BigEndian.Uint32(encoded[25:29])
	dataLen := int(binary.BigEndian.Uint16(encoded[29:31]))
	if chunk.Count == 0 || chunk.Index >= chunk.Count || dataLen > MaxChunkData {
		return Chunk{}, errors.New("tkmnet: invalid transfer chunk metadata")
	}
	for _, b := range encoded[31+dataLen:] {
		if b != 0 {
			return Chunk{}, errors.New("tkmnet: non-zero transfer chunk padding")
		}
	}
	chunk.Data = make([]byte, dataLen)
	copy(chunk.Data, encoded[31:31+dataLen])
	return chunk, nil
}

// SplitTransfer creates fixed-size chunks with one transfer identifier. The
// identifier must be treated as opaque; it is not a transaction hash.
func SplitTransfer(data []byte) ([]Chunk, error) {
	if len(data) > MaxTransferBytes {
		return nil, fmt.Errorf("tkmnet: transfer exceeds %d bytes", MaxTransferBytes)
	}
	var id [CircuitIDSize]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, fmt.Errorf("tkmnet: transfer identifier: %w", err)
	}
	count := (len(data) + MaxChunkData - 1) / MaxChunkData
	if count == 0 {
		count = 1
	}
	chunks := make([]Chunk, count)
	for i := range chunks {
		start := i * MaxChunkData
		end := start + MaxChunkData
		if end > len(data) {
			end = len(data)
		}
		chunkData := make([]byte, end-start)
		copy(chunkData, data[start:end])
		chunks[i] = Chunk{TransferID: id, Index: uint32(i), Count: uint32(count), Data: chunkData}
	}
	return chunks, nil
}

// AssembleTransfer validates and joins all chunks. It bounds the allocation
// so a relay cannot be forced to retain an unbounded transfer.
func AssembleTransfer(chunks []Chunk) ([]byte, error) {
	if len(chunks) == 0 || len(chunks) > MaxTransferBytes/MaxChunkData+1 {
		return nil, errors.New("tkmnet: invalid transfer chunk count")
	}
	first := chunks[0]
	if first.Count != uint32(len(chunks)) {
		return nil, errors.New("tkmnet: incomplete transfer")
	}
	ordered := make([][]byte, len(chunks))
	seen := make([]bool, len(chunks))
	var total int
	for _, chunk := range chunks {
		if chunk.Count != first.Count || chunk.TransferID != first.TransferID || chunk.Index >= chunk.Count || seen[chunk.Index] {
			return nil, errors.New("tkmnet: inconsistent transfer chunks")
		}
		seen[chunk.Index] = true
		ordered[chunk.Index] = chunk.Data
		total += len(chunk.Data)
		if total > MaxTransferBytes {
			return nil, errors.New("tkmnet: transfer exceeds memory limit")
		}
	}
	assembled := make([]byte, 0, total)
	for i, data := range ordered {
		if !seen[i] {
			return nil, errors.New("tkmnet: missing transfer chunk")
		}
		assembled = append(assembled, data...)
	}
	return assembled, nil
}
