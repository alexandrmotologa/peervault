# Signaling Protocol Specification

PeerVault uses an ephemeral WebSocket rendezvous relay to exchange WebRTC session descriptions (SDP) and ICE candidates.

## Wire format

All WebSocket messages are encoded as JSON objects. Payloads are encrypted client-side using XChaCha20-Poly1305 before transmission.

### 1. Join room

Sent by a client immediately after opening the WebSocket connection.

```json
{
  "action": "join",
  "room": "<64-character hex string representing HMAC-SHA256 of passphrase>",
  "role": "sender" | "receiver"
}
```

Server response:

```json
{
  "status": "joined",
  "room": "<room_id>",
  "peer_present": false | true
}
```

If a peer is already waiting in the room, `peer_present` is `true`. If two clients are already in the room, the server rejects the third client with:

```json
{
  "status": "error",
  "message": "room_full"
}
```

### 2. Forward message

Once both peers are in the room, either peer can forward encrypted payloads to the other peer:

```json
{
  "action": "signal",
  "room": "<room_id>",
  "ciphertext": "<base64 encoded encrypted payload>",
  "nonce": "<base64 encoded 24-byte nonce>"
}
```

The server forwards this message directly to the other peer connected in the same room without inspecting or parsing the ciphertext.

### Decrypted signal payloads

Peers decrypt the ciphertext using their derived signaling key. The decrypted JSON content matches one of three message types:

#### Offer (Sender -> Receiver)
```json
{
  "type": "offer",
  "sdp": "<WebRTC SDP Offer string>"
}
```

#### Answer (Receiver -> Sender)
```json
{
  "type": "answer",
  "sdp": "<WebRTC SDP Answer string>"
}
```

#### Candidate (Bidirectional)
```json
{
  "type": "candidate",
  "candidate": {
    "candidate": "candidate:...",
    "sdpMid": "0",
    "sdpMLineIndex": 0
  }
}
```

### 3. Room cleanup

The signaling server purges room resources under three conditions:
1. When either peer disconnects after WebRTC channel negotiation.
2. When 5 minutes elapse with no transfer activity.
3. If an explicit leave message is dispatched.
