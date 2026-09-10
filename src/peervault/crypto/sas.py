"""Short Authentication String (SAS) generation for visual MitM verification."""

from dataclasses import dataclass
from typing import List, Union

from cryptography.hazmat.primitives import hashes, hmac

from peervault.config import DEFAULT_CRYPTO_CONFIG, CryptoConfig

# 64 universally recognized, distinctive symbols that render cleanly across modern terminal fonts
SAS_EMOJIS: List[str] = [
    "🦊",
    "🦁",
    "🐯",
    "🐼",
    "🐨",
    "🐸",
    "🐙",
    "🐬",
    "🦉",
    "🦅",
    "🐝",
    "蝴蝶",
    "🐢",
    "🦕",
    "🐘",
    "🦒",
    "⚡",
    "🔥",
    "🌊",
    "🌈",
    "⭐",
    "🌙",
    "☀️",
    "🪐",
    "💎",
    "🔒",
    "🔑",
    "🛡️",
    "🚀",
    "🛸",
    "⛵",
    "🏎️",
    "🍕",
    "🍔",
    "🍎",
    "🍒",
    "🍇",
    "🥑",
    "🌽",
    "🍄",
    "🌲",
    "🌻",
    "🌴",
    "🌵",
    "🍀",
    "🌸",
    "🍁",
    "🌋",
    "🎸",
    "🥁",
    "🎺",
    "🎨",
    "🎯",
    "🏆",
    "👑",
    "🔮",
    "💡",
    "🧭",
    "⚓",
    "⌛",
    "📦",
    "🎈",
    "🔔",
    "🧩",
]
# Replace any multi-char with standard emoji
SAS_EMOJIS[11] = "🦋"


@dataclass(frozen=True)
class SASVerification:
    """Visual verification code derived from the negotiated session key."""

    emojis: str
    numeric: str

    @property
    def display(self) -> str:
        """Formatted representation for terminal output."""
        return f"{self.emojis}  ({self.numeric})"


def compute_sas(
    session_key: Union[bytes, bytearray],
    config: CryptoConfig = DEFAULT_CRYPTO_CONFIG,
) -> SASVerification:
    """Computes an out-of-band visual verification string from the session key.

    Uses HMAC-SHA256 with domain separation to produce:
    - 4 distinct emojis
    - 6 decimal digits formatted as XXX-XXX
    """
    h = hmac.HMAC(bytes(session_key), hashes.SHA256())
    h.update(b"peervault-sas-verification-v1")
    digest = h.finalize()

    # 1. First 4 bytes -> 6 decimal digits
    num_val = int.from_bytes(digest[:4], "big") % 1_000_000
    num_str = f"{num_val:06d}"
    formatted_num = f"{num_str[:3]}-{num_str[3:]}"

    # 2. Next 4 bytes -> 4 emojis
    chosen_emojis = [SAS_EMOJIS[digest[4 + i] % len(SAS_EMOJIS)] for i in range(4)]
    emoji_str = " ".join(chosen_emojis)

    return SASVerification(emojis=emoji_str, numeric=formatted_num)
