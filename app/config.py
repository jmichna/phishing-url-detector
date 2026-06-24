"""Konfiguracja aplikacji wczytywana ze zmiennych srodowiskowych / pliku .env."""
from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Centralne ustawienia aplikacji.

    Wartosci pochodza ze zmiennych srodowiskowych lub pliku .env.
    Aplikacja dziala bez kluczy API - wowczas klient zagrozen pracuje w trybie mock.
    """

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    threat_client_mode: str = "mock"          # "mock" lub "live"
    google_safe_browsing_api_key: str = ""
    phishtank_app_key: str = ""
    phishing_threshold: int = 50              # prog 0-100
    http_timeout: float = 5.0

    @property
    def is_live(self) -> bool:
        return self.threat_client_mode.lower() == "live"


@lru_cache
def get_settings() -> "Settings":
    """Zwraca pojedyncza instancje ustawien (cache)."""
    return Settings()
