// Copyright 2026 The TKMChain Authors.
//
// Package tkmnet contains the transport protocol used by TKMChain services.
// It carries opaque service payloads over onion relays. It deliberately does
// not parse, create, or validate blockchain transactions; Shield3 and Shield4
// remain the only consensus formats for those transactions.
package tkmnet

import (
	"bytes"
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	Magic             = "TKMN"
	Version           = 1
	MaxHops           = 3
	MaxPayload        = 2048
	CircuitIDSize     = 16
	LayerNextIDSize   = 32
	LayerBodySize     = 96
	HeaderSize        = 64
	PayloadPlainSize  = 2 + MaxPayload
	PayloadCipherSize = PayloadPlainSize + chacha20poly1305.Overhead
	LayerSize         = mlkem.CiphertextSize1024 + chacha20poly1305.NonceSizeX + LayerBodySize + chacha20poly1305.Overhead
	PacketSize        = HeaderSize + chacha20poly1305.NonceSizeX + PayloadCipherSize + MaxHops*LayerSize
	FinalRouteFlag    = 1
	maxLifetime       = 24 * time.Hour
	serviceNamePrefix = "TKMNET_SERVICE_"
)

// ServiceID identifies the application carried by a tkmnet packet. Services
// have separate encryption contexts so a packet for one service cannot be
// replayed into another service.
type ServiceID byte

const (
	ServiceTransaction ServiceID = 1
	ServiceP2P         ServiceID = 2
	ServiceMail        ServiceID = 3
	ServicePhone       ServiceID = 4
)

func (s ServiceID) valid() bool {
	return s >= ServiceTransaction && s <= ServicePhone
}

// Hop is a relay descriptor used while constructing a packet. PublicKey is
// an ML-KEM-1024 encapsulation key. ID is resolved by the caller through its
// signed onion directory; it is never used as a cryptographic key.
type Hop struct {
	ID        [LayerNextIDSize]byte
	PublicKey []byte
}

// Route is the result of opening one layer. A relay learns only the identity
// of the next relay. The payload key is present only at the final relay.
type Route struct {
	NextID     [LayerNextIDSize]byte
	Final      bool
	PayloadKey [chacha20poly1305.KeySize]byte
}

// BuildOptions controls packet construction. Exactly MaxHops relays are
// required so every packet has the same size and does not reveal the route
// length through its wire representation.
type BuildOptions struct {
	Service   ServiceID
	CircuitID [CircuitIDSize]byte
	Sequence  uint64
	Expires   uint64
	Hops      []Hop
}

// Build creates a fixed-size onion packet. The caller should send the result
// to the first relay over an onion service connection. Payload is padded and
// authenticated; it is never visible to intermediate relays.
func Build(options BuildOptions, payload []byte) ([]byte, error) {
	if !options.Service.valid() {
		return nil, errors.New("tkmnet: invalid service")
	}
	if len(payload) > MaxPayload {
		return nil, fmt.Errorf("tkmnet: payload exceeds %d bytes", MaxPayload)
	}
	if len(options.Hops) != MaxHops {
		return nil, fmt.Errorf("tkmnet: exactly %d hops are required", MaxHops)
	}
	if options.CircuitID == ([CircuitIDSize]byte{}) {
		if _, err := rand.Read(options.CircuitID[:]); err != nil {
			return nil, fmt.Errorf("tkmnet: circuit id: %w", err)
		}
	}
	if options.Sequence == 0 {
		var sequence [8]byte
		if _, err := rand.Read(sequence[:]); err != nil {
			return nil, fmt.Errorf("tkmnet: sequence: %w", err)
		}
		options.Sequence = binary.BigEndian.Uint64(sequence[:])
		if options.Sequence == 0 {
			options.Sequence = 1
		}
	}
	if options.Expires == 0 {
		options.Expires = uint64(time.Now().Add(10 * time.Minute).Unix())
	}
	now := uint64(time.Now().Unix())
	if options.Expires <= now || options.Expires-now > uint64(maxLifetime/time.Second) {
		return nil, errors.New("tkmnet: expiry is outside the permitted lifetime")
	}

	var payloadKey [chacha20poly1305.KeySize]byte
	if _, err := rand.Read(payloadKey[:]); err != nil {
		return nil, fmt.Errorf("tkmnet: payload key: %w", err)
	}
	var payloadNonce [chacha20poly1305.NonceSizeX]byte
	if _, err := rand.Read(payloadNonce[:]); err != nil {
		return nil, fmt.Errorf("tkmnet: payload nonce: %w", err)
	}
	header := encodeHeader(options.Service, 0, options.CircuitID, options.Sequence, options.Expires)
	aead, err := chacha20poly1305.NewX(payloadKey[:])
	if err != nil {
		return nil, err
	}
	plain := make([]byte, PayloadPlainSize)
	binary.BigEndian.PutUint16(plain[:2], uint16(len(payload)))
	copy(plain[2:], payload)
	payloadCipher := aead.Seal(nil, payloadNonce[:], plain, payloadAAD(header))

	layers := make([]byte, MaxHops*LayerSize)
	for i, hop := range options.Hops {
		if len(hop.PublicKey) != mlkem.EncapsulationKeySize1024 || hop.ID == ([LayerNextIDSize]byte{}) {
			return nil, fmt.Errorf("tkmnet: invalid hop %d descriptor", i)
		}
		ek, err := mlkem.NewEncapsulationKey1024(hop.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("tkmnet: hop %d public key: %w", i, err)
		}
		shared, kemCipher := ek.Encapsulate()
		key := deriveHopKey(shared, header, i)
		var nonce [chacha20poly1305.NonceSizeX]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return nil, fmt.Errorf("tkmnet: hop %d nonce: %w", i, err)
		}
		body := make([]byte, LayerBodySize)
		if i+1 < MaxHops {
			copy(body[:LayerNextIDSize], options.Hops[i+1].ID[:])
		} else {
			body[LayerNextIDSize] = FinalRouteFlag
			copy(body[LayerNextIDSize+1:], payloadKey[:])
		}
		hopCipher, err := sealLayer(key, nonce[:], body, layerAAD(header, i))
		clearBytes(shared)
		clearBytes(key)
		if err != nil {
			return nil, fmt.Errorf("tkmnet: hop %d layer: %w", i, err)
		}
		offset := i * LayerSize
		copy(layers[offset:offset+mlkem.CiphertextSize1024], kemCipher)
		offset += mlkem.CiphertextSize1024
		copy(layers[offset:offset+chacha20poly1305.NonceSizeX], nonce[:])
		offset += chacha20poly1305.NonceSizeX
		copy(layers[offset:offset+len(hopCipher)], hopCipher)
	}

	packet := make([]byte, 0, PacketSize)
	packet = append(packet, header...)
	packet = append(packet, payloadNonce[:]...)
	packet = append(packet, payloadCipher...)
	packet = append(packet, layers...)
	if len(packet) != PacketSize {
		return nil, errors.New("tkmnet: internal packet size error")
	}
	return packet, nil
}

// OpenLayer opens the layer assigned to hopIndex. The private key must be
// kept by the relay and cleared by the caller when it is no longer needed.
func OpenLayer(packet []byte, privateKey *mlkem.DecapsulationKey1024, hopIndex uint8) (Route, error) {
	var route Route
	header, err := parseHeader(packet)
	if err != nil {
		return route, err
	}
	if hopIndex >= MaxHops || header.hopIndex != hopIndex {
		return route, errors.New("tkmnet: packet is addressed to a different hop")
	}
	now := uint64(time.Now().Unix())
	if header.expires <= now {
		return route, errors.New("tkmnet: packet expired")
	}
	if header.expires-now > uint64(maxLifetime/time.Second) {
		return route, errors.New("tkmnet: packet lifetime is too long")
	}
	if privateKey == nil {
		return route, errors.New("tkmnet: missing relay private key")
	}
	offset := HeaderSize + chacha20poly1305.NonceSizeX + PayloadCipherSize + int(hopIndex)*LayerSize
	kemCipher := packet[offset : offset+mlkem.CiphertextSize1024]
	offset += mlkem.CiphertextSize1024
	nonce := packet[offset : offset+chacha20poly1305.NonceSizeX]
	offset += chacha20poly1305.NonceSizeX
	layerCipher := packet[offset : offset+LayerBodySize+chacha20poly1305.Overhead]
	shared, err := privateKey.Decapsulate(kemCipher)
	if err != nil {
		return route, errors.New("tkmnet: invalid relay layer")
	}
	key := deriveHopKey(shared, header.raw, int(hopIndex))
	body, err := openLayer(key, nonce, layerCipher, layerAAD(header.raw, int(hopIndex)))
	clearBytes(shared)
	clearBytes(key)
	if err != nil {
		return route, errors.New("tkmnet: invalid relay layer")
	}
	copy(route.NextID[:], body[:LayerNextIDSize])
	route.Final = body[LayerNextIDSize]&FinalRouteFlag != 0
	if route.Final {
		copy(route.PayloadKey[:], body[LayerNextIDSize+1:LayerNextIDSize+1+chacha20poly1305.KeySize])
		if route.NextID != ([LayerNextIDSize]byte{}) {
			return Route{}, errors.New("tkmnet: final layer has a next relay")
		}
	} else if route.NextID == ([LayerNextIDSize]byte{}) {
		return Route{}, errors.New("tkmnet: relay layer has no next relay")
	}
	return route, nil
}

// Forward advances a packet to its next relay after OpenLayer has succeeded.
// Only the hop index is changed; the packet remains fixed-size.
func Forward(packet []byte, route Route) ([]byte, error) {
	if route.Final {
		return nil, errors.New("tkmnet: final packet cannot be forwarded")
	}
	header, err := parseHeader(packet)
	if err != nil {
		return nil, err
	}
	if header.hopIndex+1 >= MaxHops {
		return nil, errors.New("tkmnet: route exhausted")
	}
	forwarded := bytes.Clone(packet)
	forwarded[6]++ // magic(4), version(1), service(1), hop index(1)
	return forwarded, nil
}

// OpenPayload decrypts the service payload at the final relay.
func OpenPayload(packet []byte, route Route) ([]byte, error) {
	if !route.Final {
		return nil, errors.New("tkmnet: payload is only available at the final relay")
	}
	header, err := parseHeader(packet)
	if err != nil {
		return nil, err
	}
	nonceStart := HeaderSize
	nonce := packet[nonceStart : nonceStart+chacha20poly1305.NonceSizeX]
	ciphertext := packet[nonceStart+chacha20poly1305.NonceSizeX : nonceStart+chacha20poly1305.NonceSizeX+PayloadCipherSize]
	aead, err := chacha20poly1305.NewX(route.PayloadKey[:])
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, nonce, ciphertext, payloadAAD(header.raw))
	if err != nil || len(plain) != PayloadPlainSize {
		return nil, errors.New("tkmnet: invalid service payload")
	}
	size := int(binary.BigEndian.Uint16(plain[:2]))
	if size > MaxPayload {
		return nil, errors.New("tkmnet: invalid service payload length")
	}
	for _, b := range plain[2+size:] {
		if b != 0 {
			return nil, errors.New("tkmnet: non-zero payload padding")
		}
	}
	return bytes.Clone(plain[2 : 2+size]), nil
}

type parsedHeader struct {
	raw       []byte
	service   ServiceID
	hopIndex  uint8
	hopCount  uint8
	circuitID [CircuitIDSize]byte
	sequence  uint64
	expires   uint64
}

func encodeHeader(service ServiceID, hopIndex uint8, circuitID [CircuitIDSize]byte, sequence, expires uint64) []byte {
	h := make([]byte, HeaderSize)
	copy(h[:4], Magic)
	h[4] = Version
	h[5] = byte(service)
	h[6] = hopIndex
	h[7] = MaxHops
	copy(h[8:8+CircuitIDSize], circuitID[:])
	binary.BigEndian.PutUint64(h[24:32], sequence)
	binary.BigEndian.PutUint64(h[32:40], expires)
	return h
}

func parseHeader(packet []byte) (parsedHeader, error) {
	var h parsedHeader
	if len(packet) != PacketSize || !bytes.Equal(packet[:4], []byte(Magic)) || packet[4] != Version {
		return h, errors.New("tkmnet: invalid packet size or version")
	}
	h.service = ServiceID(packet[5])
	if !h.service.valid() || packet[7] != MaxHops || packet[6] >= MaxHops {
		return h, errors.New("tkmnet: invalid packet header")
	}
	h.hopIndex, h.hopCount = packet[6], packet[7]
	copy(h.circuitID[:], packet[8:24])
	h.sequence = binary.BigEndian.Uint64(packet[24:32])
	h.expires = binary.BigEndian.Uint64(packet[32:40])
	if h.sequence == 0 || h.expires == 0 {
		return h, errors.New("tkmnet: invalid packet sequence or expiry")
	}
	h.raw = bytes.Clone(packet[:HeaderSize])
	return h, nil
}

func payloadAAD(header []byte) []byte {
	aad := bytes.Clone(header)
	aad[6] = 0 // The hop index advances while the packet is relayed.
	return append([]byte(serviceNamePrefix), aad...)
}

func layerAAD(header []byte, index int) []byte {
	aad := payloadAAD(header)
	return append(aad, byte(index))
}

func deriveHopKey(shared, header []byte, index int) []byte {
	info := []byte("TKMNET_MLKEM1024_HOP_KEY_V1")
	info = append(info, byte(index))
	// The hop index is mutable routing metadata. It must not change the key
	// material as the packet advances from one relay to the next.
	salt := bytes.Clone(header[:40])
	salt[6] = 0
	key, err := hkdf.Key(sha512.New, shared, salt, string(info), chacha20poly1305.KeySize)
	if err != nil {
		panic("tkmnet: hkdf key derivation failed: " + err.Error())
	}
	return key
}

func sealLayer(key, nonce, plaintext, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce, plaintext, aad), nil
}

func openLayer(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ciphertext, aad)
}

func clearBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
