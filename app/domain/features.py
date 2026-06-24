"""Ekstrakcja cech URL pod katem phishingu.

Kazda funkcja-ekstraktor przyjmuje rozlozony URL (ParsedUrl) i zwraca FeatureResult.
Cechy sa zarejestrowane w EXTRACTORS - dzieki temu warstwa serwisowa nie musi znac
ich szczegolow (zasada otwarte-zamkniete: nowa cecha = nowa funkcja + wpis na liscie).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse

import tldextract

from app.domain.models import FeatureResult

# tldextract bez pobierania listy sufiksow z sieci (dziala offline, deterministycznie)
_extract = tldextract.TLDExtract(suffix_list_urls=())

# --- Slowniki heurystyk ---------------------------------------------------

SUSPICIOUS_TLDS = {
    "zip", "review", "country", "kim", "cricket", "science", "work", "party",
    "gq", "link", "top", "click", "xyz", "tk", "ml", "ga", "cf", "rest",
}

URL_SHORTENERS = {
    "bit.ly", "goo.gl", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rebrand.ly", "shorturl.at", "rb.gy",
}

SENSITIVE_KEYWORDS = {
    "login", "signin", "secure", "account", "update", "verify", "verification",
    "banking", "confirm", "password", "credential", "wallet", "billing",
    "webscr", "ebayisapi", "paypal", "appleid",
}

IP_REGEX = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


# --- Reprezentacja rozlozonego URL ---------------------------------------

@dataclass
class ParsedUrl:
    """Znormalizowana, rozlozona postac URL uzywana przez ekstraktory."""
    raw: str
    scheme: str
    netloc: str        # host[:port]
    host: str          # sam host bez portu
    path: str
    query: str
    subdomain: str
    domain: str
    suffix: str        # TLD

    @property
    def registered_domain(self) -> str:
        return ".".join(p for p in (self.domain, self.suffix) if p)


def parse_url(url: str) -> ParsedUrl:
    """Rozklada surowy URL na czesci skladowe. Brak schematu => zakladamy http."""
    candidate = url.strip()
    if "://" not in candidate:
        candidate = "http://" + candidate
    parsed = urlparse(candidate)
    host = parsed.hostname or ""
    ext = _extract(host)
    return ParsedUrl(
        raw=url,
        scheme=parsed.scheme.lower(),
        netloc=parsed.netloc,
        host=host,
        path=parsed.path,
        query=parsed.query,
        subdomain=ext.subdomain,
        domain=ext.domain,
        suffix=ext.suffix,
    )


# --- Ekstraktory cech -----------------------------------------------------
# Sygnatura kazdej: (ParsedUrl) -> FeatureResult

def feat_length(p: ParsedUrl) -> FeatureResult:
    n = len(p.raw)
    return FeatureResult(
        name="url_length",
        description="Nadmierna dlugosc adresu URL (>75 znakow)",
        triggered=n > 75,
        weight=8,
        detail=f"dlugosc={n}",
    )


def feat_ip_host(p: ParsedUrl) -> FeatureResult:
    is_ip = bool(IP_REGEX.match(p.host))
    return FeatureResult(
        name="ip_as_host",
        description="Adres IP zamiast nazwy domeny w hoscie",
        triggered=is_ip,
        weight=20,
        detail=f"host={p.host}",
    )


def feat_at_symbol(p: ParsedUrl) -> FeatureResult:
    has_at = "@" in p.raw
    return FeatureResult(
        name="at_symbol",
        description="Znak '@' w URL (ukrywanie prawdziwego hosta)",
        triggered=has_at,
        weight=15,
        detail="znaleziono '@'" if has_at else "",
    )


def feat_subdomains(p: ParsedUrl) -> FeatureResult:
    depth = len([s for s in p.subdomain.split(".") if s]) if p.subdomain else 0
    return FeatureResult(
        name="many_subdomains",
        description="Duza liczba poddomen (>=3)",
        triggered=depth >= 3,
        weight=12,
        detail=f"poddomeny={depth}",
    )


def feat_hyphen(p: ParsedUrl) -> FeatureResult:
    count = p.domain.count("-")
    return FeatureResult(
        name="hyphen_in_domain",
        description="Myslnik w nazwie domeny (np. paypal-secure)",
        triggered=count >= 1,
        weight=8,
        detail=f"myslniki={count}",
    )


def feat_suspicious_tld(p: ParsedUrl) -> FeatureResult:
    tld = p.suffix.split(".")[-1] if p.suffix else ""
    bad = tld in SUSPICIOUS_TLDS
    return FeatureResult(
        name="suspicious_tld",
        description="Domena w podejrzanej/taniej koncowce TLD",
        triggered=bad,
        weight=12,
        detail=f"tld=.{tld}" if tld else "",
    )


def feat_homoglyph(p: ParsedUrl) -> FeatureResult:
    """Homoglyphy: punycode (xn--) lub znaki spoza ASCII w hoscie."""
    is_puny = "xn--" in p.host.lower()
    non_ascii = any(ord(ch) > 127 for ch in p.host)
    triggered = is_puny or non_ascii
    detail = "punycode" if is_puny else ("znaki spoza ASCII" if non_ascii else "")
    return FeatureResult(
        name="homoglyph_idn",
        description="Mozliwy atak homoglyphem (IDN / punycode)",
        triggered=triggered,
        weight=18,
        detail=detail,
    )


def feat_keywords(p: ParsedUrl) -> FeatureResult:
    haystack = (p.host + p.path + p.query).lower()
    hits = sorted({kw for kw in SENSITIVE_KEYWORDS if kw in haystack})
    return FeatureResult(
        name="sensitive_keywords",
        description="Slowa wrazliwe (login/verify/secure/bank...) w URL",
        triggered=bool(hits),
        weight=14,
        detail=", ".join(hits),
    )


def feat_no_https(p: ParsedUrl) -> FeatureResult:
    insecure = p.scheme != "https"
    return FeatureResult(
        name="no_https",
        description="Brak szyfrowania SSL/TLS (schemat inny niz https)",
        triggered=insecure,
        weight=10,
        detail=f"schemat={p.scheme}",
    )


def feat_shortener(p: ParsedUrl) -> FeatureResult:
    short = p.registered_domain.lower() in URL_SHORTENERS
    return FeatureResult(
        name="url_shortener",
        description="Skracacz URL ukrywajacy docelowy adres",
        triggered=short,
        weight=10,
        detail=p.registered_domain if short else "",
    )


def feat_digit_ratio(p: ParsedUrl) -> FeatureResult:
    host = p.host or ""
    digits = sum(ch.isdigit() for ch in host)
    ratio = digits / len(host) if host else 0.0
    return FeatureResult(
        name="digit_ratio",
        description="Wysoki udzial cyfr w hoscie (>30%)",
        triggered=ratio > 0.30,
        weight=8,
        detail=f"udzial_cyfr={ratio:.0%}",
    )


def feat_many_params(p: ParsedUrl) -> FeatureResult:
    params = [x for x in p.query.split("&") if x] if p.query else []
    return FeatureResult(
        name="many_query_params",
        description="Duza liczba parametrow zapytania (>=5)",
        triggered=len(params) >= 5,
        weight=6,
        detail=f"parametry={len(params)}",
    )


# Rejestr wszystkich ekstraktorow (>= 8 cech -> spelnia wymaganie minimalne).
EXTRACTORS = [
    feat_length,
    feat_ip_host,
    feat_at_symbol,
    feat_subdomains,
    feat_hyphen,
    feat_suspicious_tld,
    feat_homoglyph,
    feat_keywords,
    feat_no_https,
    feat_shortener,
    feat_digit_ratio,
    feat_many_params,
]


def extract_features(url: str) -> list[FeatureResult]:
    """Uruchamia wszystkie zarejestrowane ekstraktory dla podanego URL."""
    parsed = parse_url(url)
    return [extractor(parsed) for extractor in EXTRACTORS]
