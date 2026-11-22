"""Process-memory sessions. Key bytes never appear in repr or JSON."""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass, field

from eg_crypto import Keyring
from eg_crypto.envelope import fingerprint

SESSION_TTL = 8 * 60 * 60
MAX_SESSIONS = 200
MAX_KEYS = 16


def _wipe(buf: bytearray) -> None:
    for index in range(len(buf)):
        buf[index] = 0


@dataclass
class Session:
    created: float
    expires: float
    keys: dict[str, bytearray] = field(default_factory=dict)
    order: list[str] = field(default_factory=list)
    current: str | None = None
    key_created: dict[str, float] = field(default_factory=dict)
    key_retired: dict[str, float] = field(default_factory=dict)
    key_lock: threading.RLock = field(default_factory=threading.RLock, repr=False)
    inventory: dict[str, dict[str, dict[str, str]]] = field(
        default_factory=lambda: {kind: {} for kind in ("tenants", "sites", "devices")}
    )
    inventory_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def wipe(self) -> None:
        with self.key_lock:
            for material in self.keys.values():
                _wipe(material)
            self.keys.clear()
            self.order.clear()
            self.current = None
            self.key_created.clear()
            self.key_retired.clear()
            with self.inventory_lock:
                for records in self.inventory.values():
                    records.clear()

    def keyring(self) -> Keyring:
        with self.key_lock:
            if not self.current or self.current not in self.keys:
                raise LookupError("no key")
            public = {kid: bytes(material) for kid, material in self.keys.items()}
            return Keyring(public, self.current)

    def add_key(self) -> tuple[str, str]:
        with self.key_lock:
            if len(self.keys) >= MAX_KEYS:
                raise ValueError("too many keys")
            number = 1
            while f"k{number}" in self.keys:
                number += 1
            kid = f"k{number}"
            material = bytearray(secrets.token_bytes(32))
            self.keys[kid] = material
            self.order.append(kid)
            now = time.time()
            if self.current:
                self.key_retired[self.current] = now
            self.key_created[kid] = now
            self.current = kid
            return kid, fingerprint(bytes(material))

    def public_keys(self) -> list[dict[str, object]]:
        with self.key_lock:
            rows = []
            for kid in self.order:
                material = self.keys.get(kid)
                if material is None:
                    continue
                rows.append(
                    {
                        "kid": kid,
                        "fingerprint": fingerprint(bytes(material)),
                        "current": kid == self.current,
                        "rotation_status": "current" if kid == self.current else "retired",
                        "created_unix": self.key_created[kid],
                        "retired_unix": self.key_retired.get(kid),
                    }
                )
            return rows

    def shred(self, kid: str) -> str:
        with self.key_lock:
            if kid == self.current or kid not in self.keys:
                raise ValueError("cannot shred")
            fp = fingerprint(bytes(self.keys[kid]))
            _wipe(self.keys.pop(kid))
            self.order = [item for item in self.order if item != kid]
            self.key_created.pop(kid, None)
            self.key_retired.pop(kid, None)
            return fp


class Store:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._sessions: dict[str, Session] = {}

    def reset(self) -> None:
        with self._lock:
            for session in self._sessions.values():
                session.wipe()
            self._sessions.clear()

    def _purge(self, now: float) -> None:
        expired = [sid for sid, session in self._sessions.items() if session.expires <= now]
        for sid in expired:
            self._sessions.pop(sid).wipe()

    def create(self) -> tuple[str, Session]:
        with self._lock:
            now = time.time()
            self._purge(now)
            if len(self._sessions) >= MAX_SESSIONS:
                raise RuntimeError("busy")
            sid = secrets.token_urlsafe(32)
            session = Session(created=now, expires=now + SESSION_TTL)
            self._sessions[sid] = session
            return sid, session

    def get(self, token: str) -> Session | None:
        if not token:
            return None
        with self._lock:
            session = self._sessions.get(token)
            if session is None:
                return None
            if session.expires <= time.time():
                self._sessions.pop(token, None)
                session.wipe()
                return None
            return session

    def drop(self, token: str) -> None:
        with self._lock:
            session = self._sessions.pop(token, None)
            if session is not None:
                session.wipe()
