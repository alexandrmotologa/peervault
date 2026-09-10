# peervault

Peer-to-peer file transfer and secret sharing CLI using WebRTC DataChannels and authenticated encryption.

When sharing production keys, SSL certificates, or local database dumps, uploading them to team chat or pastebins leaves plaintext copies on external servers. Setting up cloud buckets or SSH access takes time and requires firewall changes.

PeerVault connects two computers directly through WebRTC. Transfers stream memory to memory with XChaCha20-Poly1305 authenticated encryption and an ephemeral X25519 key exchange. No file contents ever pass through a relay or touch disk on an intermediate server.

## Features

- Direct peer-to-peer transfers over WebRTC DataChannels using public STUN servers
- End-to-end encryption with XChaCha20-Poly1305 and Argon2id key derivation
- Ephemeral X25519 Diffie-Hellman handshake for forward secrecy
- Human-readable code phrases formatted as `[number]-[adjective]-[noun]` (for example, `7-copper-falcon`)
- Terminal QR code rendering for scanning from a second screen or mobile device
- Memory scrubbing that zeroes encryption keys after transfer
- Direct stdin and stdout piping for shell workflows
- Safe directory archiving with built-in path traversal checks
- Self-contained WebSocket signaling server with in-memory state and automatic room expiry

## Installation

### Using uv (recommended)

```bash
uv tool install git+https://github.com/alexandrmotologa/peervault.git
```

### From source

```bash
git clone https://github.com/alexandrmotologa/peervault.git
cd peervault
uv sync
```

## Quickstart

### 1. Send a file

```bash
peervault send .env.production
```

PeerVault displays a code phrase such as `7-copper-falcon` and a terminal QR code:

```text
Code: 7-copper-falcon
Waiting for receiver to connect...
```

### 2. Receive a file

On the receiving machine:

```bash
peervault receive 7-copper-falcon
```

The transfer begins automatically once the WebRTC connection establishes.

### 3. Piping secrets through standard input and output

Send directly from standard input without saving a temporary file:

```bash
echo "DATABASE_URL=postgres://user:secret@db.internal:5432/app" | peervault send -
```

On the receiving machine, write directly to standard output or pipe to another program:

```bash
peervault receive 7-copper-falcon - > .env.local
```

### 4. Sending directories

Pass any folder path to send an in-memory tarball:

```bash
peervault send ./configs/
```

The receiver unpacks the files safely, blocking any entries that attempt directory traversal.

## How it works

1. **Code phrase generation**: The sender creates a random code phrase such as `4-amber-badger`.
2. **Encrypted signaling**: Both peers connect to an ephemeral WebSocket signaling server. The room ID is a SHA-256 hash of the passphrase and salt, so the relay cannot see the phrase. All SDP offers, answers, and ICE candidates are encrypted with an Argon2id-derived key before transmission.
3. **P2P hole punching**: Peers exchange ICE candidates to discover direct public or local IP routes via STUN servers.
4. **DataChannel establishment**: The machines open an ordered, reliable WebRTC DataChannel. The signaling connection closes immediately.
5. **In-band forward secrecy**: Peers perform an ephemeral X25519 Diffie-Hellman exchange over the DataChannel, deriving the session key through HKDF-SHA256.
6. **Encrypted transfer**: Data is split into 64 KB chunks, encrypted with XChaCha20-Poly1305 with unique nonces, and streamed directly between peers.
7. **Verification and cleanup**: The receiver checks the SHA-256 digest of the reassembled payload. Both peers scrub cryptographic keys from memory.

## Self-hosting the signaling server

PeerVault includes a standalone WebSocket signaling server. It stores all room state in memory and purges rooms after 5 minutes of inactivity:

```bash
peervault server --host 0.0.0.0 --port 8765
```

Clients can point to your relay with the `--relay` flag or the `PEERVAULT_RELAY` environment variable:

```bash
export PEERVAULT_RELAY="wss://relay.example.com"
peervault send secret.key
```

## Security architecture

Read the detailed security specifications in [docs/security.md](docs/security.md) and architecture details in [docs/architecture.md](docs/architecture.md).

## License

MIT License. See [LICENSE](LICENSE) for details.
