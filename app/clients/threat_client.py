"""Klient zewnetrznych zrodel zagrozen: Google Safe Browsing oraz PhishTank.

Obsluguje dwa tryby (ustawiane w .env przez THREAT_CLIENT_MODE):
  * "mock" - bez sieci; deterministyczna heurystyka demonstracyjna (domyslny),
  * "live" - realne zapytania HTTP do zewnetrznych API.

W trybie live klient pyta po kolei dostepne zrodla i zwraca pierwsze trafienie:
  1. Google Safe Browsing  - tylko gdy podano GOOGLE_SAFE_BROWSING_API_KEY,
  2. PhishTank             - dziala takze bez klucza (nizszy limit zapytan).

Dzieki wspolnemu interfejsowi ThreatClient pozostale warstwy nie wiedza,
ktore zrodlo odpowiedzialo - mozna je dodawac/usuwac bez zmian w detektorze.
"""
from __future__ import annotations

import requests

from app.clients.base import ThreatClient
from app.config import Settings
from app.domain.models import BlacklistResult

# Domeny "znane" jako zlosliwe w trybie mock (do demonstracji/testow offline).
_MOCK_KNOWN_BAD = {
    "paypal-secure-login.tk",
    "verify-account-update.xyz",
    "malware-test.com",
}

# Uwaga: Safe Browsing v4 jest oznaczone jako deprecated (nastepca: v5 / Web Risk API),
# ale endpoint wciaz dziala i wystarcza do projektu edukacyjnego.
GSB_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
PHISHTANK_ENDPOINT = "https://checkurl.phishtank.com/checkurl/"

# PhishTank wymaga opisowego User-Agent - bez niego zapytania sa ograniczane.
_USER_AGENT = "phishing-url-detector/1.0 (projekt edukacyjny)"


class ExternalThreatClient(ThreatClient):
    """Adapter do zewnetrznych API z bezpiecznym trybem mock."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def check(self, url: str) -> BlacklistResult:
        if self._settings.is_live:
            return self._check_live(url)
        return self._check_mock(url)

    # --- tryb offline -----------------------------------------------------
    def _check_mock(self, url: str) -> BlacklistResult:
        low = url.lower()
        for bad in _MOCK_KNOWN_BAD:
            if bad in low:
                return BlacklistResult(
                    listed=True, source="mock",
                    detail=f"dopasowano znana zlosliwa domene '{bad}'",
                )
        return BlacklistResult(listed=False, source="mock")

    # --- tryb live: pyta dostepne zrodla, pierwsze trafienie wygrywa ------
    def _check_live(self, url: str) -> BlacklistResult:
        last: BlacklistResult | None = None
        if self._settings.google_safe_browsing_api_key:
            last = self._check_google(url)
            if last.listed:
                return last
        last = self._check_phishtank(url)
        return last

    # --- Google Safe Browsing (v4 Lookup) ---------------------------------
    def _check_google(self, url: str) -> BlacklistResult:
        payload = {
            "client": {"clientId": "phishing-url-detector", "clientVersion": "1.0.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        try:
            resp = requests.post(
                GSB_ENDPOINT,
                params={"key": self._settings.google_safe_browsing_api_key},
                json=payload,
                timeout=self._settings.http_timeout,
            )
            resp.raise_for_status()
            data = resp.json()
        except (requests.RequestException, ValueError) as exc:
            # Degradacja: brak sieci / blad API nie wywraca aplikacji.
            return BlacklistResult(listed=False, source="google_safe_browsing",
                                   detail=f"blad zapytania: {exc}")
        if data.get("matches"):
            kinds = ", ".join(sorted({m.get("threatType", "?") for m in data["matches"]}))
            return BlacklistResult(listed=True, source="google_safe_browsing", detail=kinds)
        return BlacklistResult(listed=False, source="google_safe_browsing")

    # --- PhishTank (checkurl) ---------------------------------------------
    def _check_phishtank(self, url: str) -> BlacklistResult:
        data = {"url": url, "format": "json"}
        if self._settings.phishtank_app_key:
            data["app_key"] = self._settings.phishtank_app_key
        try:
            resp = requests.post(
                PHISHTANK_ENDPOINT,
                data=data,
                headers={"User-Agent": _USER_AGENT},
                timeout=self._settings.http_timeout,
            )
            resp.raise_for_status()
            payload = resp.json()
        except (requests.RequestException, ValueError) as exc:
            return BlacklistResult(listed=False, source="phishtank",
                                   detail=f"blad zapytania: {exc}")
        results = payload.get("results", {}) if isinstance(payload, dict) else {}
        if results.get("in_database") and results.get("valid"):
            return BlacklistResult(
                listed=True, source="phishtank",
                detail=f"phish_id={results.get('phish_id')}",
            )
        return BlacklistResult(listed=False, source="phishtank")
