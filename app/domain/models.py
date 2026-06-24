"""Modele domenowe (czyste struktury danych)."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Verdict(str, Enum):
    """Werdykt koncowy analizy."""
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    PHISHING = "phishing"


@dataclass
class FeatureResult:
    """Wynik pojedynczej cechy analizowanego URL.

    Attributes:
        name: techniczna nazwa cechy.
        description: opis czytelny dla czlowieka.
        triggered: czy cecha wskazuje na phishing.
        weight: waga cechy w scoringu (0-100).
        detail: dodatkowy kontekst (np. zmierzona wartosc).
    """
    name: str
    description: str
    triggered: bool
    weight: int
    detail: str = ""


@dataclass
class BlacklistResult:
    """Wynik sprawdzenia w zewnetrznych/lokalnych listach zagrozen."""
    listed: bool
    source: str          # np. "local", "phishtank", "google_safe_browsing", "mock"
    detail: str = ""


@dataclass
class AnalysisResult:
    """Zagregowany wynik analizy pojedynczego URL."""
    url: str
    score: int                                  # 0-100
    verdict: Verdict
    features: list[FeatureResult] = field(default_factory=list)
    blacklist: BlacklistResult | None = None

    @property
    def triggered_features(self) -> list[FeatureResult]:
        return [f for f in self.features if f.triggered]
