"""Logika scoringu: zamienia liste cech + wynik blacklisty na ocene 0-100 i werdykt."""
from __future__ import annotations

from app.domain.models import AnalysisResult, BlacklistResult, FeatureResult, Verdict

# Trafienie na blackliscie jest rozstrzygajace - dodaje duzy ladunek punktowy.
BLACKLIST_WEIGHT = 60


def compute_score(features: list[FeatureResult], blacklist: BlacklistResult | None) -> int:
    """Sumuje wagi uruchomionych cech (+ ewentualnie blackliste), normalizuje do 0-100."""
    raw = sum(f.weight for f in features if f.triggered)
    if blacklist and blacklist.listed:
        raw += BLACKLIST_WEIGHT
    return max(0, min(100, raw))


def decide_verdict(score: int, threshold: int) -> Verdict:
    """Mapuje wynik liczbowy na werdykt wg progu."""
    if score >= threshold:
        return Verdict.PHISHING
    if score >= max(1, threshold // 2):
        return Verdict.SUSPICIOUS
    return Verdict.SAFE


def build_result(
    url: str,
    features: list[FeatureResult],
    blacklist: BlacklistResult | None,
    threshold: int,
) -> AnalysisResult:
    """Buduje kompletny AnalysisResult na podstawie cech i blacklisty."""
    score = compute_score(features, blacklist)
    verdict = decide_verdict(score, threshold)
    return AnalysisResult(
        url=url, score=score, verdict=verdict, features=features, blacklist=blacklist
    )
