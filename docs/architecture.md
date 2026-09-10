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
        | 6. XChaCha20-Poly1305 Encrypted 64 KB Chunks       |
        |===================================================>|
        |                                                    |
        | 7. SHA-256 integrity check and key memory zeroing  |
```

## System components

### 1. Cryptographic engine (`peervault.crypto`)
- `kdf.py`: Derives 256-bit symmetric keys using Argon2id with memory cost of 64 MB, time cost of 3 passes, and parallelism of 4 threads. Also generates blinded room IDs for signaling.
- `cipher.py`: Wraps XChaCha20-Poly1305 AEAD. Formats frames with chunk index, payload length, 24-byte nonce, and 16-byte authentication tag.
- `dh.py`: Generates ephemeral X25519 keypairs. Derives transmission keys by combining the Argon2id passphrase key and the X25519 shared secret via HKDF-SHA256.
- `memory.py`: Explicitly overwrites key bytearrays with zeros before reference release.

### 2. Rendezvous signaling (`peervault.signaling`)
- `words.py`: Generates passphrases structured as `[1-99]-[adjective]-[noun]` drawn from clean wordlists with strong phonetic distinction.
- `protocol.py`: Wire messages for room joining, encrypted SDP offers and answers, and ICE candidates.
- `server.py`: Async WebSocket server managing rooms in memory. Rooms close when two peers finish connecting or when a 5-minute inactivity timer fires.
- `client.py`: Asynchronous client managing websocket connection lifecycle and payload encryption.

### 3. P2P transport (`peervault.p2p`)
- `connection.py`: Wraps `aiortc.RTCPeerConnection`. Queries public STUN servers to discover external IP candidates and handles ICE gathering state.
- `channel.py`: Configures `RTCDataChannel` in ordered and reliable mode. Enforces flow control by monitoring `bufferedAmount` to prevent buffer bloat during high-speed local network transfers.

### 4. Transfer coordinator (`peervault.transfer`)
- `sender.py`: Reads files, streams, or directories into 64 KB frames, encrypts each frame, and dispatches them across the data channel with progress callbacks.
- `receiver.py`: Collects and validates incoming frames, writes chunks to target destinations, and verifies matching SHA-256 file hashes.
- `archive.py`: Converts directory trees into in-memory tar.gz streams on the fly and unpacks them with strict Zip-Slip path sanitization.

### 5. Terminal user interface (`peervault.ui`)
- `qr.py`: Produces ANSI terminal QR codes via `segno` for mobile or camera scanning.
- `progress.py`: Rich terminal widgets reporting transfer speed (MB/s), total payload size, percentage complete, and elapsed time.
