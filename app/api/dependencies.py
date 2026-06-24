# Budowa zaleznosci (wstrzykiwanie) dla warstwy API.
from __future__ import annotations

from functools import lru_cache

from app.clients.local_blacklist import LocalBlacklistClient
from app.clients.threat_client import ExternalThreatClient
from app.config import get_settings
from app.services.detector import PhishingDetector


@lru_cache
def get_detector() -> PhishingDetector:
    # Skladuje detektor z lokalna blacklista + klientem zewnetrznym (mock/live).
    settings = get_settings()
    clients = [
        LocalBlacklistClient(),
        ExternalThreatClient(settings),
    ]
    return PhishingDetector(clients=clients, threshold=settings.phishing_threshold)
