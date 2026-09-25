package tkmnet

import (
	"bytes"
	"crypto/mlkem"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto/pqcrypto"
	"golang.org/x/crypto/chacha20poly1305"
)

func testHops(t *testing.T) ([]Hop, []*mlkem.DecapsulationKey1024) {
	t.Helper()
	hops := make([]Hop, MaxHops)
	keys := make([]*mlkem.DecapsulationKey1024, MaxHops)
	for i := range hops {
		key, err := mlkem.GenerateKey1024()
		if err != nil {
			t.Fatal(err)
		}
		keys[i] = key
		hops[i].PublicKey = key.EncapsulationKey().Bytes()
		hops[i].ID[0] = byte(i + 1)
	}
	return hops, keys
}

func TestBuildOpenForwardAndPayload(t *testing.T) {
	hops, keys := testHops(t)
	packet, err := Build(BuildOptions{Service: ServiceTransaction, Hops: hops}, []byte("shielded transaction bytes"))
	if err != nil {
		t.Fatal(err)
	}
	if len(packet) != PacketSize {
		t.Fatalf("packet size = %d, want %d", len(packet), PacketSize)
	}
	var seen [MaxHops]Route
	for i := 0; i < MaxHops; i++ {
		route, err := OpenLayer(packet, keys[i], uint8(i))
		if err != nil {
			t.Fatalf("open layer %d: %v", i, err)
		}
		seen[i] = route
		if i < MaxHops-1 {
			if route.Final || route.NextID[0] != byte(i+2) {
				t.Fatalf("layer %d route = %+v", i, route)
			}
			packet, err = Forward(packet, route)
			if err != nil {
				t.Fatalf("forward layer %d: %v", i, err)
			}
		}
	}
	if !seen[MaxHops-1].Final {
		t.Fatal("last layer is not final")
	}
	got, err := OpenPayload(packet, seen[MaxHops-1])
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "shielded transaction bytes" {
		t.Fatalf("payload = %q", got)
	}
}

func TestPacketTamperingAndWrongKeyFail(t *testing.T) {
	hops, keys := testHops(t)
	packet, err := Build(BuildOptions{Service: ServiceMail, Hops: hops}, []byte("private mail"))
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := mlkem.GenerateKey1024()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenLayer(packet, wrong, 0); err == nil {
		t.Fatal("wrong relay key accepted")
	}
	layerOffset := HeaderSize + chacha20poly1305.NonceSizeX + PayloadCipherSize
	packet[layerOffset+mlkem.CiphertextSize1024+chacha20poly1305.NonceSizeX] ^= 1
	if _, err := OpenLayer(packet, keys[0], 0); err == nil {
		t.Fatal("tampered packet accepted")
	}
}

func TestServicesAndPayloadLimits(t *testing.T) {
	hops, _ := testHops(t)
	for _, service := range []ServiceID{ServiceTransaction, ServiceP2P, ServiceMail, ServicePhone} {
		packet, err := Build(BuildOptions{Service: service, Hops: hops}, bytes.Repeat([]byte{7}, MaxPayload))
		if err != nil || len(packet) != PacketSize {
			t.Fatalf("service %d: packet=%d err=%v", service, len(packet), err)
		}
	}
	if _, err := Build(BuildOptions{Service: ServicePhone, Hops: hops}, bytes.Repeat([]byte{1}, MaxPayload+1)); err == nil {
		t.Fatal("oversized payload accepted")
	}
}

func TestReplayCache(t *testing.T) {
	c, err := NewReplayCache(2, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	var circuit [CircuitIDSize]byte
	circuit[0] = 1
	now := time.Unix(1000, 0)
	if err := c.Accept(circuit, 1, 1300, now); err != nil {
		t.Fatal(err)
	}
	if err := c.Accept(circuit, 1, 1300, now); err != ErrReplay {
		t.Fatalf("duplicate error = %v", err)
	}
	if err := c.Accept(circuit, 2, 1300, now); err != nil {
		t.Fatal(err)
	}
	if err := c.Accept(circuit, 3, 1300, now); err != ErrCacheFull {
		t.Fatalf("full error = %v", err)
	}
	if err := c.Accept(circuit, 3, 1300, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
}

func TestTransportUsesFixedPackets(t *testing.T) {
	hops, _ := testHops(t)
	packet, err := Build(BuildOptions{Service: ServiceP2P, Hops: hops}, []byte("p2p"))
	if err != nil {
		t.Fatal(err)
	}
	var wire bytes.Buffer
	if err := WritePacket(&wire, packet); err != nil {
		t.Fatal(err)
	}
	got, err := ReadPacket(&wire)
	if err != nil || !bytes.Equal(got, packet) {
		t.Fatalf("read packet err=%v equal=%v", err, bytes.Equal(got, packet))
	}
}

func TestServiceLifecycleAndPersistentRelayKey(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "relay", "key")
	svc, err := NewService(ServiceConfig{Enabled: true, ListenAddr: "127.0.0.1:0", OnionOnly: true, PrivateKeyPath: keyPath})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Start(); err != nil {
		t.Fatal(err)
	}
	if svc.Addr() == nil || len(svc.PublicKey()) != mlkem.EncapsulationKeySize1024 {
		t.Fatal("service did not expose a running endpoint and relay key")
	}
	id := svc.RelayID()
	if err := svc.Stop(); err != nil {
		t.Fatal(err)
	}
	svc2, err := NewService(ServiceConfig{Enabled: true, ListenAddr: "127.0.0.1:0", OnionOnly: true, PrivateKeyPath: keyPath})
	if err != nil {
		t.Fatal(err)
	}
	if svc2.RelayID() != id {
		t.Fatal("relay identity changed after restart")
	}
}

func TestTransferChunking(t *testing.T) {
	input := bytes.Repeat([]byte("shielded transaction payload"), 1000)
	chunks, err := SplitTransfer(input)
	if err != nil {
		t.Fatal(err)
	}
	encoded := make([]Chunk, len(chunks))
	for i, chunk := range chunks {
		wire, err := EncodeChunk(chunk)
		if err != nil {
			t.Fatal(err)
		}
		encoded[i], err = DecodeChunk(wire)
		if err != nil {
			t.Fatal(err)
		}
	}
	for i, j := 0, len(encoded)-1; i < j; i, j = i+1, j-1 {
		encoded[i], encoded[j] = encoded[j], encoded[i]
	}
	output, err := AssembleTransfer(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(output, input) {
		t.Fatal("assembled transfer differs from input")
	}
	empty, err := SplitTransfer(nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := AssembleTransfer(empty); err != nil || len(got) != 0 {
		t.Fatalf("empty transfer = %d bytes, err=%v", len(got), err)
	}
}

func TestSignedRelayDescriptor(t *testing.T) {
	key, err := pqcrypto.GenerateMLDSA87()
	if err != nil {
		t.Fatal(err)
	}
	kem, err := mlkem.GenerateKey1024()
	if err != nil {
		t.Fatal(err)
	}
	d := Descriptor{Version: Version, Onion: strings.Repeat("a", 56) + ".onion", PublicKey: kem.EncapsulationKey().Bytes(), SigningPublicKey: pqcrypto.PublicKeyBytes(key), Expires: uint64(time.Now().Add(time.Hour).Unix())}
	copy(d.ID[:], relayIDDigest(d.PublicKey))
	if err := SignDescriptor(&d, func(message []byte) ([]byte, error) { return pqcrypto.SignMLDSA87(key, message) }); err != nil {
		t.Fatal(err)
	}
	if err := d.Verify(time.Now()); err != nil {
		t.Fatal(err)
	}
	d.Onion = "bad.example"
	if err := d.Verify(time.Now()); err == nil {
		t.Fatal("invalid onion descriptor accepted")
	}
}
