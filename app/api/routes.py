# Definicje endpointow REST.
from __future__ import annotations

from fastapi import APIRouter, Depends

from app.api.dependencies import get_detector
from app.api.schemas import (
    AnalyzeRequest,
    AnalyzeResponse,
    BatchAnalyzeRequest,
)
from app.config import get_settings
from app.services.detector import PhishingDetector

router = APIRouter()


@router.get("/health", tags=["meta"])
def health() -> dict:
    s = get_settings()
    return {"status": "ok", "threat_client_mode": s.threat_client_mode,
            "phishing_threshold": s.phishing_threshold}


@router.post("/analyze", response_model=AnalyzeResponse, tags=["analiza"])
def analyze(req: AnalyzeRequest,
            detector: PhishingDetector = Depends(get_detector)) -> AnalyzeResponse:
    result = detector.analyze(req.url)
    return AnalyzeResponse.from_domain(result)


@router.post("/analyze/batch", response_model=list[AnalyzeResponse], tags=["analiza"])
def analyze_batch(req: BatchAnalyzeRequest,
                  detector: PhishingDetector = Depends(get_detector)) -> list[AnalyzeResponse]:
    results = detector.analyze_many(req.urls)
    return [AnalyzeResponse.from_domain(r) for r in results]
