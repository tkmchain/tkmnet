package tkmnet

import (
	"context"
	"crypto/mlkem"
	"net"
	"path/filepath"
	"testing"
	"time"
)

func TestServiceOpensFinalPayload(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "relay", "key")
	opened := make(chan []byte, 1)
	svc, err := NewService(ServiceConfig{
		Enabled:        true,
		ListenAddr:     "127.0.0.1:0",
		OnionOnly:      true,
		HopIndex:       2,
		PrivateKeyPath: keyPath,
		Handler: func(_ context.Context, route Route, packet []byte) ([]byte, error) {
			payload, err := OpenPayload(packet, route)
			if err == nil {
				opened <- payload
			}
			return nil, err
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Start(); err != nil {
		t.Fatal(err)
	}
	defer svc.Stop()

	hops := make([]Hop, MaxHops)
	keys := make([]*mlkem.DecapsulationKey1024, 2)
	for i := 0; i < 2; i++ {
		key, err := mlkem.GenerateKey1024()
		if err != nil {
			t.Fatal(err)
		}
		keys[i] = key
		hops[i].PublicKey = key.EncapsulationKey().Bytes()
		hops[i].ID[0] = byte(i + 1)
	}
	hops[2] = Hop{PublicKey: svc.PublicKey()}
	hops[2].ID = svc.RelayID()
	packet, err := Build(BuildOptions{Service: ServicePhone, Hops: hops}, []byte("encrypted phone message"))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		route, err := OpenLayer(packet, keys[i], uint8(i))
		if err != nil {
			t.Fatal(err)
		}
		packet, err = Forward(packet, route)
		if err != nil {
			t.Fatal(err)
		}
	}
	conn, err := net.DialTimeout("tcp", svc.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := WritePacket(conn, packet); err != nil {
		conn.Close()
		t.Fatal(err)
	}
	_ = conn.Close()
	select {
	case got := <-opened:
		if string(got) != "encrypted phone message" {
			t.Fatalf("payload = %q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("service handler did not receive the packet")
	}
}

func TestServiceRejectsPublicListener(t *testing.T) {
	_, err := NewService(ServiceConfig{Enabled: true, ListenAddr: "0.0.0.0:39000", OnionOnly: true, PrivateKeyPath: filepath.Join(t.TempDir(), "key")})
	if err == nil {
		t.Fatal("public tkmnet listener accepted")
	}
}
