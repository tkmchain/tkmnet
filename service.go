package tkmnet

import (
	"context"
	"crypto/mlkem"
	"crypto/sha512"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ServiceConfig configures the local tkmnet relay endpoint. The endpoint is
// intentionally a local listener: Tor publishes it as an onion service and
// no public TCP socket is opened by this package.
type ServiceConfig struct {
	Enabled        bool
	ListenAddr     string
	OnionOnly      bool
	HopIndex       uint8
	PrivateKeyPath string
	ReplayCache    *ReplayCache
	Handler        Handler
	Logger         func(message string, args ...any)
}

// Handler receives one opened relay layer. For a final route, callers should
// call OpenPayload and dispatch it to the service selected by the packet. For
// a non-final route, callers forward the packet through their signed directory.
// A non-empty returned packet is written back on the same connection.
type Handler func(context.Context, Route, []byte) ([]byte, error)

// Service implements node.Lifecycle without importing the node package. It
// can therefore be registered directly with gtkm's protocol stack.
type Service struct {
	cfg      ServiceConfig
	listener net.Listener
	key      *mlkem.DecapsulationKey1024
	replay   *ReplayCache
	stopOnce sync.Once
	stop     chan struct{}
	wg       sync.WaitGroup
}

func NewService(cfg ServiceConfig) (*Service, error) {
	if !cfg.Enabled {
		return &Service{cfg: cfg}, nil
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = "127.0.0.1:0"
	}
	if cfg.HopIndex >= MaxHops {
		return nil, errors.New("tkmnet: hop index is outside the supported range")
	}
	if !isLoopbackListenAddr(cfg.ListenAddr) {
		return nil, errors.New("tkmnet: relay service must listen on loopback; publish it through Tor")
	}
	if cfg.PrivateKeyPath == "" {
		return nil, errors.New("tkmnet: relay private key path is required")
	}
	if cfg.ReplayCache == nil {
		var err error
		cfg.ReplayCache, err = NewReplayCache(100_000, 30*time.Minute)
		if err != nil {
			return nil, err
		}
	}
	key, err := loadOrCreateRelayKey(cfg.PrivateKeyPath)
	if err != nil {
		return nil, err
	}
	return &Service{cfg: cfg, key: key, replay: cfg.ReplayCache, stop: make(chan struct{})}, nil
}

func (s *Service) Start() error {
	if s == nil || !s.cfg.Enabled {
		return nil
	}
	if s.listener != nil {
		return errors.New("tkmnet: service already started")
	}
	listener, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("tkmnet: listen on %s: %w", s.cfg.ListenAddr, err)
	}
	s.listener = listener
	s.log("tkmnet relay started", "listen", listener.Addr().String(), "hop", s.cfg.HopIndex, "relayID", s.RelayID())
	s.wg.Add(1)
	go s.acceptLoop()
	return nil
}

func (s *Service) Stop() error {
	if s == nil || !s.cfg.Enabled {
		return nil
	}
	s.stopOnce.Do(func() {
		close(s.stop)
		if s.listener != nil {
			_ = s.listener.Close()
		}
	})
	s.wg.Wait()
	return nil
}

func (s *Service) Addr() net.Addr {
	if s == nil || s.listener == nil {
		return nil
	}
	return s.listener.Addr()
}

// PublicKey returns a copy of the relay's ML-KEM encapsulation key.
func (s *Service) PublicKey() []byte {
	if s == nil || s.key == nil {
		return nil
	}
	return append([]byte(nil), s.key.EncapsulationKey().Bytes()...)
}

// RelayID is the stable directory identifier for this relay key.
func (s *Service) RelayID() [LayerNextIDSize]byte {
	var id [LayerNextIDSize]byte
	if s == nil || s.key == nil {
		return id
	}
	copy(id[:], relayIDDigest(s.key.EncapsulationKey().Bytes()))
	return id
}

func (s *Service) acceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.stop:
				return
			default:
			}
			s.log("tkmnet relay accept failed", "error", err)
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleConn(conn)
		}()
	}
}

func (s *Service) handleConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	packet, err := ReadPacket(conn)
	if err != nil {
		return
	}
	header, err := parseHeader(packet)
	if err != nil || header.hopIndex != s.cfg.HopIndex {
		return
	}
	route, err := OpenLayer(packet, s.key, s.cfg.HopIndex)
	if err != nil {
		return
	}
	if err := s.replay.Accept(header.circuitID, header.sequence, header.expires, time.Now()); err != nil {
		return
	}
	if s.cfg.Handler == nil {
		return
	}
	response, err := s.cfg.Handler(context.Background(), route, packet)
	if err != nil || len(response) == 0 {
		return
	}
	_ = WritePacket(conn, response)
}

func (s *Service) log(message string, args ...any) {
	if s.cfg.Logger != nil {
		s.cfg.Logger(message, args...)
	}
}

func loadOrCreateRelayKey(path string) (*mlkem.DecapsulationKey1024, error) {
	if data, err := os.ReadFile(path); err == nil {
		key, err := mlkem.NewDecapsulationKey1024(data)
		if err != nil {
			return nil, fmt.Errorf("tkmnet: invalid relay key: %w", err)
		}
		return key, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("tkmnet: read relay key: %w", err)
	}
	key, err := mlkem.GenerateKey1024()
	if err != nil {
		return nil, fmt.Errorf("tkmnet: generate relay key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, fmt.Errorf("tkmnet: create relay key directory: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, key.Bytes(), 0600); err != nil {
		return nil, fmt.Errorf("tkmnet: write relay key: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return nil, fmt.Errorf("tkmnet: install relay key: %w", err)
	}
	return key, nil
}

func isLoopbackListenAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return host == "localhost" || (ip != nil && ip.IsLoopback())
}

func relayIDDigest(data []byte) []byte {
	// Keep the relay identifier independent from the transaction hash and
	// from any address format used by the chain.
	// SHA-512 is available in the standard library and is already used by the
	// Shield3 transcript. Truncation here is an identifier, not a signature.
	h := sha512.Sum512(data)
	return append([]byte(nil), h[:LayerNextIDSize]...)
}
