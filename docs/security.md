# Security Model and Threat Analysis

PeerVault transfers confidential files without trusting relay infrastructure or intermediate networks.

## Cryptographic specifications

### Key derivation (Argon2id)
Passphrases such as `7-copper-falcon` provide high memorability but lower raw entropy than 256-bit random keys. To make offline brute-force and dictionary attacks impractical:
- Algorithm: Argon2id (RFC 9106)
- Memory cost: 65,536 KiB (64 MB)
- Time cost: 3 iterations
- Parallelism: 4 threads
- Salt: Static protocol salt combined with domain separation prefixes (`peervault-v1-signaling` and `peervault-v1-transfer`)

### Signaling blind room IDs
The rendezvous signaling server never receives the passphrase. Instead:
`RoomID = HMAC-SHA256(Key = "peervault-signaling-v1", Message = Passphrase)`
Only peers knowing the exact passphrase can compute the matching RoomID.

### Encrypted signaling messages
SDP offers, SDP answers, and ICE candidate strings exchanged through the relay are encrypted with an ephemeral key derived from the passphrase using AES-256-GCM or XChaCha20-Poly1305. A compromised or hostile signaling relay sees only encrypted bytes and opaque room IDs, preventing it from inspecting peer IP addresses or altering SDP parameters.

### In-band forward secrecy (X25519 Ephemeral Diffie-Hellman)
To protect against retroactive decryption if a passphrase is later compromised:
1. Each peer generates an ephemeral X25519 keypair when the WebRTC DataChannel opens.
2. The peers exchange their public keys over the DataChannel.
3. Both sides compute the shared secret: `DiffieHellmanSecret = X25519(PrivateA, PublicB)`.
4. The final transfer session key is derived through HKDF-SHA256:
   `SessionKey = HKDF(Salt = Argon2idPassphraseKey, IKM = DiffieHellmanSecret, Info = "peervault-datachannel-v1")`.

Even an attacker who records encrypted WebRTC network traffic and later recovers the human code phrase cannot decrypt the stream because the ephemeral private keys never leave volatile memory.

### Authenticated chunk encryption (XChaCha20-Poly1305)
- Stream payload is divided into 64 KB (65,536 bytes) chunks.
- Each chunk uses XChaCha20-Poly1305 with an independent 24-byte cryptographically secure random nonce.
- Frame header includes:
  - 4 bytes: chunk index (unsigned integer)
  - 4 bytes: plaintext length (unsigned integer)
  - 24 bytes: nonce
  - 16 bytes: Poly1305 authentication tag
- Modifying any byte in transit causes immediate decryption failure and transfer termination.

### Memory sanitization
Keys, intermediate key material, and shared secrets are stored in mutable `bytearray` buffers. Once a transfer completes or fails, an explicit memory zeroing routine overwrites the underlying buffers with zeros before references are dereferenced.

## Threat analysis

| Threat | Mitigation |
|---|---|
| Malicious signaling relay | Signaling server only sees room hashes; all payloads are encrypted with the passphrase-derived key before transmission. Relay never receives file contents. |
| Network wiretap / ISP snooping | Data travels through encrypted WebRTC DTLS and nested XChaCha20-Poly1305 encryption. |
| Replay attacks | Every transfer uses unique ephemeral nonces and independent session keypairs. |
| Stolen code phrase after transfer | In-band X25519 key exchange guarantees forward secrecy. Compromising the phrase after completion does not decrypt recorded traffic. |
| Path traversal (Zip-Slip) | Tar extraction inspects normalized target paths and rejects any entry containing directory traversal elements or absolute path components. |
