"""Message types and constants for the signaling protocol."""

from dataclasses import dataclass
from typing import Any, Dict, Optional


class Action:
    JOIN = "join"
    SIGNAL = "signal"
    LEAVE = "leave"


class Status:
    JOINED = "joined"
    PEER_JOINED = "peer_joined"
    PEER_LEFT = "peer_left"
    ERROR = "error"


@dataclass
class SignalingEnvelope:
    action: str
    room: str
    ciphertext: Optional[str] = None
    nonce: Optional[str] = None
    role: Optional[str] = None
    extra: Optional[Dict[str, Any]] = None
