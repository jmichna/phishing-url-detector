# Klient lokalnej blacklisty - czyta wzorce domen z pliku data/blacklist.txt.
from __future__ import annotations

from pathlib import Path

from app.clients.base import ThreatClient
from app.domain.models import BlacklistResult

_DATA = Path(__file__).resolve().parent.parent.parent / "data" / "blacklist.txt"


class LocalBlacklistClient(ThreatClient):

    def __init__(self, path: Path | None = None) -> None:
        self._path = path or _DATA
        self._patterns = self._load()

    def _load(self) -> list[str]:
        if not self._path.exists():
            return []
        lines = self._path.read_text(encoding="utf-8").splitlines()
        return [ln.strip().lower() for ln in lines if ln.strip() and not ln.startswith("#")]

    def check(self, url: str) -> BlacklistResult:
        low = url.lower()
        for pattern in self._patterns:
            if pattern in low:
                return BlacklistResult(listed=True, source="local", detail=f"wzorzec '{pattern}'")
        return BlacklistResult(listed=False, source="local")
