# Schematy Pydantic (kontrakt wejscia/wyjscia REST API).
from __future__ import annotations

from pydantic import BaseModel, Field

from app.domain.models import AnalysisResult


class AnalyzeRequest(BaseModel):
    url: str = Field(..., examples=["http://paypal-secure-login.tk/account/verify"])


class BatchAnalyzeRequest(BaseModel):
    urls: list[str] = Field(..., max_length=100,
                            examples=[["https://google.com", "http://bit.ly/x"]])


class FeatureOut(BaseModel):
    name: str
    description: str
    triggered: bool
    weight: int
    detail: str = ""


class BlacklistOut(BaseModel):
    listed: bool
    source: str
    detail: str = ""


class AnalyzeResponse(BaseModel):
    url: str
    score: int
    verdict: str
    triggered_count: int
    features: list[FeatureOut]
    blacklist: BlacklistOut | None = None

    @classmethod
    def from_domain(cls, r: AnalysisResult) -> "AnalyzeResponse":
        return cls(
            url=r.url,
            score=r.score,
            verdict=r.verdict.value,
            triggered_count=len(r.triggered_features),
            features=[FeatureOut(**f.__dict__) for f in r.features],
            blacklist=BlacklistOut(**r.blacklist.__dict__) if r.blacklist else None,
        )
