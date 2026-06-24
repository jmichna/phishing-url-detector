# Interfejs (port) klienta listy zagrozen.
from __future__ import annotations

from typing import Protocol

from app.domain.models import BlacklistResult


class ThreatClient(Protocol):
    # Port: dowolne zrodlo sprawdzajace, czy URL jest znanym zagrozeniem.

    def check(self, url: str) -> BlacklistResult:
        ...
