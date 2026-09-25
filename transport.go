package tkmnet

import (
	"context"
	"errors"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"

	xproxy "golang.org/x/net/proxy"
)

// SOCKS5Dialer is a fail-closed dialer for tkmnet onion services. It never
// falls back to a direct socket and rejects IP literals and clearnet DNS names.
type SOCKS5Dialer struct {
	dialer xproxy.Dialer
}

func NewSOCKS5Dialer(proxyURL string) (*SOCKS5Dialer, error) {
	u, err := url.Parse(proxyURL)
	if err != nil || u.Scheme != "socks5" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("tkmnet: SOCKS5 proxy must be socks5://host:port")
	}
	if _, err := strconv.ParseUint(u.Port(), 10, 16); err != nil {
		return nil, errors.New("tkmnet: SOCKS5 proxy port is invalid")
	}
	d, err := xproxy.SOCKS5("tcp", u.Host, nil, xproxy.Direct)
	if err != nil {
		return nil, err
	}
	return &SOCKS5Dialer{dialer: d}, nil
}

func (d *SOCKS5Dialer) DialContext(ctx context.Context, onionHost string, port string) (net.Conn, error) {
	if d == nil || d.dialer == nil {
		return nil, errors.New("tkmnet: SOCKS5 dialer is not configured")
	}
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(onionHost), "."))
	if !strings.HasSuffix(host, ".onion") {
		return nil, errors.New("tkmnet: only .onion destinations are allowed")
	}
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		return nil, errors.New("tkmnet: destination port is invalid")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	result := make(chan struct {
		conn net.Conn
		err  error
	}, 1)
	go func() {
		conn, err := d.dialer.Dial("tcp", net.JoinHostPort(host, port))
		result <- struct {
			conn net.Conn
			err  error
		}{conn, err}
	}()
	select {
	case r := <-result:
		return r.conn, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// WritePacket writes exactly one fixed-size packet. There is no length field
// on the wire, which prevents packet-size metadata from exposing the service
// payload size.
func WritePacket(w io.Writer, packet []byte) error {
	if len(packet) != PacketSize {
		return errors.New("tkmnet: invalid packet size")
	}
	for len(packet) > 0 {
		written, err := w.Write(packet)
		if err != nil {
			return err
		}
		if written <= 0 || written > len(packet) {
			return io.ErrShortWrite
		}
		packet = packet[written:]
	}
	return nil
}

func ReadPacket(r io.Reader) ([]byte, error) {
	packet := make([]byte, PacketSize)
	if _, err := io.ReadFull(r, packet); err != nil {
		return nil, err
	}
	return packet, nil
}
