# tkmnet

`tkmnet` is TKMChain's encrypted service transport. It is deliberately kept
outside consensus: Shield3 and Shield4 transaction encoding, proof checking,
nullifier handling, and stamp rules are unchanged.

## Protocol properties

- Fixed-size packets (`PacketSize`) for all four services: transactions, P2P,
  email, and phone.
- Three relay layers using FIPS 203 ML-KEM-1024 and XChaCha20-Poly1305.
- A relay can decrypt only its own route layer and learns only the next relay
  identifier. The final relay receives the service payload.
- Payloads are padded and authenticated with a service-specific context.
- Circuit/sequence replay protection is bounded by `ReplayCache`.
- `SOCKS5Dialer` accepts only `.onion` destinations and never falls back to a
  direct connection.

`tkmnet` does not make public blockchain data private. Shield3/Shield4 provide
ledger privacy; tkmnet protects transport origin and service payloads.

## Integration boundary

The package implements `node.Lifecycle` and is registered by `gtkm` when
`--tkmnet.enable` is set. It listens only on the local side of a Tor onion
service, uses a separate `~/.tkmchain/tkmnet` state directory, and exposes no
clearnet listener. The node owns startup and shutdown ordering: stopping the
node cancels the relay context, closes active connections, and waits for all
relay goroutines to exit.

The package is published at
[`github.com/tkmchain/tkmnet`](https://github.com/tkmchain/tkmnet). TKMChain
currently compiles the matching copy in its main module so the transport and
consensus code are released together.
