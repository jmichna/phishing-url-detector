from app.clients.local_blacklist import LocalBlacklistClient
from app.clients.threat_client import ExternalThreatClient
from app.config import get_settings
from app.domain.features import EXTRACTORS
from app.services.detector import PhishingDetector


def _detector() -> PhishingDetector:
    s = get_settings()
    return PhishingDetector(
        clients=[LocalBlacklistClient(), ExternalThreatClient(s)],
        threshold=s.phishing_threshold,
    )


def test_min_eight_features():
    assert len(EXTRACTORS) >= 8


def test_safe_url():
    assert _detector().analyze("https://www.google.com").verdict.value == "safe"


def test_blacklisted_url_is_phishing():
    assert _detector().analyze("https://malware-test.com/x").verdict.value == "phishing"


def test_heuristic_phishing_url():
    r = _detector().analyze("http://paypal-secure-login.tk/account/verify?id=1")
    assert r.verdict.value == "phishing"
    assert r.score >= 50


def test_batch():
    res = _detector().analyze_many(["https://google.com", "https://malware-test.com"])
    assert len(res) == 2
