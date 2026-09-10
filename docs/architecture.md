# Architecture

PeerVault operates on a zero-persistence model where sensitive data streams directly between two peers.

```
+---------------+                                    +---------------+
|  Alice (Send) |                                    |  Bob (Receive)|
+-------+-------+                                    +-------+-------+
        |                                                    |
        | 1. Connect and join room (HMAC-derived ID)         | 2. Join room
        +--------------------\              /----------------+
                              \            /
                        +------v----------v-----+
                        | Ephemeral WebSocket   |
                        | Signaling Relay       |
                        +-----------------------+
                              /            \
        +--------------------/              \----------------+
        | 3. Exchange encrypted SDP and ICE candidates       |
        |                                                    |
        | 4. Direct WebRTC DataChannel (IP-to-IP)            |
        |<==================================================>|
        |                                                    |
        | 5. In-band Ephemeral X25519 Handshake              |
        |<-------------------------------------------------->|
        |                                                    |
        | 6. SAS Visual Verification (4 Emojis + 6 Digits)   |
        |<..................................................>|
        |                                                    |
        | 7. ChaCha20-Poly1305 Encrypted 64 KB Chunks        |
        |===================================================>|
        |                                                    |
        | 8. SHA-256 integrity check and key memory zeroing  |
```

## System components

### 1. Cryptographic engine (`peervault.crypto`)
- `kdf.py`: Derives 256-bit symmetric keys using Argon2id with memory cost of 64 MB, time cost of 3 passes, and parallelism of 4 threads. Also generates blinded room IDs for signaling.
- `cipher.py`: Wraps ChaCha20-Poly1305 AEAD. Formats frames with chunk index, payload length, 12-byte nonce (session salt + counter), and 16-byte authentication tag.
- `dh.py`: Generates ephemeral X25519 keypairs. Derives transmission keys by combining the Argon2id passphrase key and the X25519 shared secret via HKDF-SHA256.
- `sas.py`: Computes out-of-band visual verification codes (4 emojis and 6 decimal digits) from the negotiated session key using HMAC-SHA256.
- `memory.py`: Overwrites key bytearrays with zeros before reference release.

### 2. Rendezvous signaling (`peervault.signaling`)
- `words.py`: Generates passphrases structured as `[1-99]-[adjective]-[noun]` drawn from clean wordlists with strong phonetic distinction.
- `protocol.py`: Wire messages for room joining, encrypted SDP offers and answers, and ICE candidates.
- `server.py`: Async WebSocket server managing rooms in memory and serving the embedded web receiver via HTTP on the same port.
- `client.py`: Asynchronous client managing websocket connection lifecycle and payload encryption.

### 3. Local discovery (`peervault.discovery`)
- `lan.py`: Local network peer discovery via UDP broadcast on port 8766. Allows direct connections without any external signaling server or internet access.

### 4. P2P transport (`peervault.p2p`)
- `connection.py`: Wraps `aiortc.RTCPeerConnection`. Queries public STUN servers to discover external IP candidates and handles ICE gathering state.
- `channel.py`: Configures `RTCDataChannel` in ordered and reliable mode. Enforces flow control by monitoring `bufferedAmount` to prevent buffer bloat during high-speed local network transfers.

### 5. Transfer coordinator (`peervault.transfer`)
- `sender.py`: Reads files, streams, or directories into 64 KB frames, encrypts each frame, and dispatches them across the data channel. Supports resumable streaming and live file updates.
- `receiver.py`: Collects and validates incoming frames, tracks chunk progress via checkpoints, writes chunks to target destinations, and verifies matching SHA-256 file hashes.
- `checkpoint.py`: Tracks chunk completion in `.peervault.part` and `.peervault.meta` to allow resuming interrupted downloads.
- `clipboard.py`: Direct clipboard reader and writer with auto-clearing timer for safe in-memory token transfers.
- `watcher.py`: File monitoring engine detecting file changes and streaming live updates across the open channel.
- `archive.py`: Converts directory trees and multi-file batches into in-memory tar.gz streams on the fly and unpacks them with strict Zip-Slip path sanitization.

### 6. User interface (`peervault.ui`)
- `qr.py`: Produces ANSI terminal QR codes via `segno` for mobile or camera scanning.
- `progress.py`: Rich terminal widgets reporting transfer speed (MB/s), total payload size, percentage complete, and elapsed time.

### 7. Universal web receiver (`peervault.web`)
- `index.html`: Self-contained, responsive single-page WebRTC application with zero external dependencies. Connects to the relay, negotiates DataChannels, and downloads files directly into the browser.
