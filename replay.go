package tkmnet

import (
	"encoding/binary"
	"errors"
	"sync"
	"time"
)

var (
	ErrReplay    = errors.New("tkmnet: replayed packet")
	ErrCacheFull = errors.New("tkmnet: replay cache is full")
)

// ReplayCache rejects a circuit/sequence pair more than once. It is bounded
// to prevent an unauthenticated peer from exhausting relay memory.
type ReplayCache struct {
	mu      sync.Mutex
	entries map[[CircuitIDSize + 8]byte]time.Time
	max     int
	ttl     time.Duration
}

func NewReplayCache(maxEntries int, ttl time.Duration) (*ReplayCache, error) {
	if maxEntries < 1 || maxEntries > 1_000_000 {
		return nil, errors.New("tkmnet: replay cache size is outside the permitted range")
	}
	if ttl <= 0 || ttl > 24*time.Hour {
		return nil, errors.New("tkmnet: replay cache ttl is outside the permitted range")
	}
	return &ReplayCache{entries: make(map[[CircuitIDSize + 8]byte]time.Time), max: maxEntries, ttl: ttl}, nil
}

// Accept records a packet and returns ErrReplay if the same packet was seen
// before. expires is the packet's Unix expiry and is checked independently of
// the cache TTL.
func (c *ReplayCache) Accept(circuitID [CircuitIDSize]byte, sequence, expires uint64, now time.Time) error {
	if c == nil || sequence == 0 || expires <= uint64(now.Unix()) {
		return errors.New("tkmnet: invalid replay identity or expiry")
	}
	key := [CircuitIDSize + 8]byte{}
	copy(key[:CircuitIDSize], circuitID[:])
	binary.BigEndian.PutUint64(key[CircuitIDSize:], sequence)
	c.mu.Lock()
	defer c.mu.Unlock()
	cutoff := now.Add(-c.ttl)
	for k, seen := range c.entries {
		if seen.Before(cutoff) {
			delete(c.entries, k)
		}
	}
	if _, ok := c.entries[key]; ok {
		return ErrReplay
	}
	if len(c.entries) >= c.max {
		return ErrCacheFull
	}
	c.entries[key] = now
	return nil
}
