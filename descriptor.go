package tkmnet

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/crypto/pqcrypto"
)

// Descriptor is a signed relay advertisement. The onion hostname and ML-KEM
// key are authenticated together, so a directory cannot substitute a key for
// a relay while retaining its identifier.
type Descriptor struct {
	Version   uint8
	ID        [LayerNextIDSize]byte
	Onion     string
	PublicKey []byte
	// SigningPublicKey authenticates the descriptor independently from the
	// relay's ML-KEM key used for packet layers.
	SigningPublicKey []byte
	Expires          uint64
	Signature        []byte
}

func (d Descriptor) signingBytes() ([]byte, error) {
	if d.Version != Version || d.ID == ([LayerNextIDSize]byte{}) || len(d.PublicKey) != 1568 || len(d.SigningPublicKey) != pqcrypto.MLDSA87PublicKeySize || d.Expires == 0 {
		return nil, errors.New("tkmnet: invalid relay descriptor")
	}
	onion, err := validateOnionHostname(d.Onion)
	if err != nil {
		return nil, err
	}
	if len(onion) > 255 {
		return nil, errors.New("tkmnet: onion hostname is too long")
	}
	buf := bytes.NewBuffer(nil)
	buf.WriteString("TKMNET_DESCRIPTOR_V1")
	buf.WriteByte(d.Version)
	buf.Write(d.ID[:])
	buf.WriteByte(byte(len(onion)))
	buf.WriteString(onion)
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(d.PublicKey)))
	buf.Write(length[:])
	buf.Write(d.PublicKey)
	binary.BigEndian.PutUint16(length[:], uint16(len(d.SigningPublicKey)))
	buf.Write(length[:])
	buf.Write(d.SigningPublicKey)
	var expiry [8]byte
	binary.BigEndian.PutUint64(expiry[:], d.Expires)
	buf.Write(expiry[:])
	return buf.Bytes(), nil
}

// SignDescriptor signs a canonical relay descriptor with ML-DSA-87. The
// callback keeps this package independent from private key storage.
func SignDescriptor(d *Descriptor, sign func([]byte) ([]byte, error)) error {
	if d == nil || sign == nil {
		return errors.New("tkmnet: descriptor signer is missing")
	}
	message, err := d.signingBytes()
	if err != nil {
		return err
	}
	signature, err := sign(message)
	if err != nil {
		return err
	}
	if len(signature) == 0 {
		return errors.New("tkmnet: empty descriptor signature")
	}
	d.Signature = append([]byte(nil), signature...)
	return nil
}

func (d Descriptor) Verify(now time.Time) error {
	message, err := d.signingBytes()
	if err != nil {
		return err
	}
	if d.Expires <= uint64(now.Unix()) || d.Expires-uint64(now.Unix()) > uint64(maxLifetime/time.Second) {
		return errors.New("tkmnet: relay descriptor is expired or too far in the future")
	}
	wantID := relayIDDigest(d.PublicKey)
	if !bytes.Equal(d.ID[:], wantID) {
		return errors.New("tkmnet: relay descriptor identifier does not match its key")
	}
	if !pqcrypto.VerifyMLDSA87(d.SigningPublicKey, message, d.Signature) {
		return errors.New("tkmnet: invalid relay descriptor signature")
	}
	return nil
}

func validateOnionHostname(value string) (string, error) {
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
	if !strings.HasSuffix(host, ".onion") {
		return "", errors.New("tkmnet: relay descriptor requires a .onion hostname")
	}
	label := strings.TrimSuffix(host, ".onion")
	if len(label) != 56 {
		return "", fmt.Errorf("tkmnet: onion hostname has invalid length %d", len(label))
	}
	for _, c := range label {
		if !(c >= 'a' && c <= 'z' || c >= '2' && c <= '7') {
			return "", errors.New("tkmnet: onion hostname is not a v3 base32 name")
		}
	}
	return host, nil
}
