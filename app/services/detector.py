"""Serwis-orkiestrator: laczy ekstrakcje cech, klientow zagrozen i scoring."""
from __future__ import annotations

from app.clients.base import ThreatClient
from app.domain.features import extract_features
from app.domain.models import AnalysisResult, BlacklistResult
from app.services.scoring import build_result


class PhishingDetector:
    """Glowny serwis aplikacji.

    Nie zna szczegolow HTTP ani frameworka - dostaje gotowych klientow
    (wstrzykniecie zaleznosci), co ulatwia testowanie i podmiane zrodel.
    """

    def __init__(self, clients: list[ThreatClient], threshold: int) -> None:
        self._clients = clients
        self._threshold = threshold

    def _check_blacklists(self, url: str) -> BlacklistResult | None:
        """Pierwsze trafienie wygrywa; w przeciwnym razie zwraca wynik 'czysto'."""
        last: BlacklistResult | None = None
        for client in self._clients:
            result = client.check(url)
            last = result
            if result.listed:
                return result
        return last

    def analyze(self, url: str) -> AnalysisResult:
        """Pelna analiza pojedynczego URL."""
        features = extract_features(url)
        blacklist = self._check_blacklists(url)
        return build_result(url, features, blacklist, self._threshold)

    def analyze_many(self, urls: list[str]) -> list[AnalysisResult]:
        """Analiza wsadowa (batch)."""
        return [self.analyze(u) for u in urls]
