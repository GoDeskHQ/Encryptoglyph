"""Scoped API tokens for connections (Konektor, n8n, scripts).

A token is created by the holder of a console session and acts on that session's
keyring only. Custody stays process-memory: the plaintext token is shown once,
only its SHA-256 hash is kept, and nothing here is written to disk. A token
cannot shred keys or mint other tokens; those stay session-only.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import threading
import time
from dataclasses import dataclass, field

PREFIX = "egt_"
SCOPES = ("keys:read", "keys:write", "seal", "open", "rewrap", "blind-index", "backup")
DEFAULT_TTL = 7 * 24 * 60 * 60
MAX_TTL = 30 * 24 * 60 * 60
MIN_TTL = 60 * 60
MAX_TOKENS_PER_SESSION = 20
_NAME = re.compile(r"^[A-Za-z0-9 ._:-]{1,64}$")


def _digest(plain: str) -> str:
    return hashlib.sha256(plain.encode()).hexdigest()


@dataclass
class TokenRecord:
    id: str
    name: str
    scopes: tuple[str, ...]
    created: float
    expires: float
    session_id: str = field(repr=False)
    token_hash: str = field(repr=False)
    prefix: str = ""
    last_used: float = 0.0

    def public(self) -> dict[str, object]:
        return {
            "id": self.id,
            "name": self.name,
            "scopes": list(self.scopes),
            "prefix": self.prefix,
            "created_unix": int(self.created),
            "expires_unix": int(self.expires),
            "last_used_unix": int(self.last_used) if self.last_used else None,
        }


def parse_scopes(raw: object) -> tuple[str, ...] | None:
    if isinstance(raw, str):
        raw = [part for part in re.split(r"[\s,]+", raw) if part]
    if not isinstance(raw, list) or not raw or len(raw) > len(SCOPES):
        return None
    out: list[str] = []
    for item in raw:
        if not isinstance(item, str) or item not in SCOPES:
            return None
        if item not in out:
            out.append(item)
    return tuple(out)


def parse_ttl(body: dict) -> int | None:
    days = body.get("expires_in_days")
    if days is None:
        return DEFAULT_TTL
    if isinstance(days, bool) or not isinstance(days, (int, float)):
        return None
    ttl = int(days * 24 * 60 * 60)
    if ttl < MIN_TTL or ttl > MAX_TTL:
        return None
    return ttl


class TokenStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._by_hash: dict[str, TokenRecord] = {}

    def reset(self) -> None:
        with self._lock:
            self._by_hash.clear()

    def _purge(self, now: float) -> None:
        for key in [k for k, rec in self._by_hash.items() if rec.expires <= now]:
            self._by_hash.pop(key, None)

    def create(
        self, session_id: str, name: str, scopes: tuple[str, ...], ttl: int
    ) -> tuple[str, TokenRecord]:
        if not _NAME.fullmatch(name or ""):
            raise ValueError("invalid name")
        with self._lock:
            now = time.time()
            self._purge(now)
            if (
                sum(1 for rec in self._by_hash.values() if rec.session_id == session_id)
                >= MAX_TOKENS_PER_SESSION
            ):
                raise ValueError("too many tokens")
            plain = PREFIX + secrets.token_urlsafe(32)
            record = TokenRecord(
                id="tok_" + secrets.token_hex(6),
                name=name,
                scopes=scopes,
                created=now,
                expires=now + ttl,
                session_id=session_id,
                token_hash=_digest(plain),
                prefix=plain[: len(PREFIX) + 6],
            )
            self._by_hash[record.token_hash] = record
            return plain, record

    def list(self, session_id: str) -> list[dict[str, object]]:
        with self._lock:
            self._purge(time.time())
            rows = [rec for rec in self._by_hash.values() if rec.session_id == session_id]
        return [rec.public() for rec in sorted(rows, key=lambda rec: rec.created)]

    def revoke(self, session_id: str, token_id: str) -> bool:
        with self._lock:
            for key, rec in list(self._by_hash.items()):
                if rec.id == token_id and rec.session_id == session_id:
                    self._by_hash.pop(key)
                    return True
        return False

    def drop_session(self, session_id: str) -> None:
        with self._lock:
            for key in [k for k, rec in self._by_hash.items() if rec.session_id == session_id]:
                self._by_hash.pop(key, None)

    def resolve(self, plain: str) -> TokenRecord | None:
        if not plain.startswith(PREFIX) or len(plain) > 128:
            return None
        digest = _digest(plain)
        with self._lock:
            now = time.time()
            for key, rec in self._by_hash.items():
                if hmac.compare_digest(key, digest):
                    if rec.expires <= now:
                        self._by_hash.pop(key, None)
                        return None
                    rec.last_used = now
                    return rec
        return None

    def latest_expiry(self, session_id: str) -> float:
        with self._lock:
            return max(
                (rec.expires for rec in self._by_hash.values() if rec.session_id == session_id),
                default=0.0,
            )
