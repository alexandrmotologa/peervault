<p align="center">
  <img src="docs/images/logo.png?raw=true" alt="PeerVault Logo" width="140" style="border-radius: 28px;" />
</p>

<h1 align="center">PeerVault</h1>

<p align="center">
  <strong>Direct peer-to-peer ephemeral secret sharing and file transfer over WebRTC.</strong><br />
  Memory-to-memory streaming with end-to-end authenticated encryption, zero server persistence, and zero disk leaks.
</p>

<p align="center">
  <a href="https://github.com/alexandrmotologa/peervault/actions"><img src="https://img.shields.io/badge/tests-40%20passed-success?style=flat-square&logo=githubactions&logoColor=white" alt="Tests" /></a>
  <img src="https://img.shields.io/badge/python-3.10%20|%203.11%20|%203.12-blue?style=flat-square&logo=python&logoColor=white" alt="Python" />
  <img src="https://img.shields.io/badge/p2p-WebRTC%20DataChannel-blueviolet?style=flat-square" alt="WebRTC" />
  <img src="https://img.shields.io/badge/crypto-ChaCha20--Poly1305%20%2B%20X25519-0ea5e9?style=flat-square" alt="Crypto" />
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License" />
</p>

<p align="center">
  <img src="docs/images/terminal_transfer.png?raw=true" alt="PeerVault Terminal P2P Transfer CLI" width="850" style="border-radius: 12px; box-shadow: 0 16px 36px rgba(0,0,0,0.4);" />
</p>

## Overview

When sharing production keys, SSL certificates, or local database dumps, uploading them to team chat or pastebins leaves plaintext copies on external servers. Setting up cloud buckets or SSH access takes time and requires firewall changes.

PeerVault connects two computers directly through WebRTC. Transfers stream memory to memory with XChaCha20-Poly1305 authenticated encryption and an ephemeral X25519 key exchange. No file contents ever pass through a relay or touch disk on an intermediate server.

## Features

- Direct peer-to-peer transfers over WebRTC DataChannels using public STUN servers
- End-to-end encryption with XChaCha20-Poly1305 and Argon2id key derivation
- Ephemeral X25519 Diffie-Hellman handshake for forward secrecy
- Visual Short Authentication String (SAS) with 4 emojis and 6 digits to verify active connection authenticity
- Human-readable code phrases formatted as `[number]-[adjective]-[noun]` (for example, `7-copper-falcon`)
- Multi-file and mixed folder batch transfers in a single command
- Zero-disk system clipboard sync (`peervault clip send` and `peervault clip receive`) with auto-clear timer
- Live file watch mode (`--watch`) that syncs modifications across the open channel in real time
- Resumable chunked transfers with automatic checkpoint recovery
- Offline local LAN discovery (`--lan`) over UDP broadcast without internet or external servers
- Embedded web browser receiver accessible directly from desktop and mobile browsers
- User configuration file (`config.toml`) managed via `peervault config`
- Direct stdin and stdout piping for shell workflows
- Safe directory archiving with built-in path traversal checks
- Self-contained WebSocket signaling relay with in-memory state and automatic room expiry

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

### 1. Send files or directories

Send a single file:

```bash
peervault send .env.production
```

Send multiple files and directories as a batch:

```bash
peervault send cert.pem key.pem ./configs/
```

PeerVault displays a code phrase such as `7-copper-falcon` and a terminal QR code:

```text
Passphrase code: 7-copper-falcon
Waiting for receiver to connect...
```

### 2. Receive files

On the receiving machine:

```bash
peervault receive 7-copper-falcon
```

PeerVault displays an interactive preview of the incoming file and verifies connection authenticity using the visual SAS code:

```text
Security Code (SAS): 🦊 ⚡ 💎 🚀  (684-219)

Incoming transfer: cert.pem (1.4 KB)
Accept file download? [Y/n]: y
```

To skip the interactive prompt in automated scripts, pass `--yes`:

```bash
peervault receive 7-copper-falcon --yes
```

### 3. Clipboard sync

Copy an API key, SSH token, or password directly into the receiver's system clipboard without writing anything to disk:

```bash
# On sender (reads system clipboard):
peervault clip send

# On receiver (copies directly to clipboard, clears in 45s):
peervault clip receive 7-copper-falcon --clear 45
```

### 4. Live sync / Watch mode

Keep the WebRTC channel open and sync file edits to a remote server or colleague in real time:

```bash
peervault send .env.local --watch
```

Whenever you save changes to `.env.local`, PeerVault encrypts and streams the updated version immediately across the existing connection.

### 5. Offline local network transfer (LAN)

If both computers are connected to the same local Wi-Fi or office network, bypass external signaling relays entirely:

```bash
# On sender:
peervault send dump.sql --lan

# On receiver:
peervault receive 7-copper-falcon --lan
```

Peers discover each other over UDP broadcast on port 8766. No internet connection or public STUN server is required.

### 6. Embedded web browser receiver

Anyone on a phone or machine without Python installed can receive files through a browser. When running the signaling server:

```bash
peervault server --host 0.0.0.0 --port 8765
```

Open `http://<server-ip>:8765/` in Chrome, Safari, or Firefox, enter the passphrase code, and download the file directly via browser WebRTC.

<p align="center">
  <img src="docs/images/web_receiver.png?raw=true" alt="PeerVault WebRTC Browser Receiver" width="560" style="border-radius: 12px; box-shadow: 0 16px 36px rgba(0,0,0,0.4);" />
</p>


### 7. Piping secrets through standard input and output

Send directly from standard input without saving a temporary file:

```bash
echo "DATABASE_URL=postgres://user:secret@db.internal:5432/app" | peervault send -
```

On the receiving machine, write directly to standard output or pipe to another command:

```bash
peervault receive 7-copper-falcon - > .env.local
```

### 8. Configuration file

PeerVault supports persistent configuration settings (`config.toml`):

```bash
# Generate a documented template
peervault config init

# View active settings and config location
peervault config show
```

## How it works

1. **Code phrase generation**: The sender creates a random code phrase such as `4-amber-badger`.
2. **Encrypted signaling**: Both peers connect to an ephemeral WebSocket signaling server (or discover each other via LAN UDP broadcast). The room ID is an HMAC blind hash of the passphrase, so the relay cannot see the phrase. All SDP offers, answers, and ICE candidates are encrypted with an Argon2id-derived key before transmission.
3. **P2P hole punching**: Peers exchange ICE candidates to discover direct public or local IP routes via STUN servers.
4. **DataChannel establishment**: The machines open an ordered, reliable WebRTC DataChannel.
5. **In-band forward secrecy**: Peers perform an ephemeral X25519 Diffie-Hellman exchange over the DataChannel, deriving the final session key through HKDF-SHA256.
6. **Visual SAS verification**: Both terminals display identical 4-emoji and 6-digit authentication strings derived from the session key to prevent active MitM tampering.
7. **Encrypted transfer & checkpointing**: Data is split into 64 KB chunks, encrypted with XChaCha20-Poly1305 with unique nonces, and streamed. If interrupted, the receiver resumes from the last confirmed chunk.
8. **Integrity verification & memory scrubbing**: The receiver validates the SHA-256 digest of the reassembled payload. Both peers wipe cryptographic keys from memory immediately upon completion.

## Self-hosting the signaling server

PeerVault includes an in-memory WebSocket signaling server with zero database requirements:

```bash
peervault server --host 0.0.0.0 --port 8765
```

Clients can point to your relay with the `--relay` flag, `config.toml`, or the `PEERVAULT_RELAY` environment variable:

```bash
export PEERVAULT_RELAY="wss://relay.example.com"
peervault send secret.key
```

## Security specifications

Read the full cryptographic threat model in [docs/security.md](docs/security.md) and architecture details in [docs/architecture.md](docs/architecture.md).

## License

MIT License. See [LICENSE](LICENSE) for details.
