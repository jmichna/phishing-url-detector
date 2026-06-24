"""Punkt wejscia aplikacji FastAPI (montaz routera, frontend, metadane, CORS)."""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app import __version__
from app.api.routes import router

_STATIC_DIR = Path(__file__).resolve().parent / "static"


def create_app() -> FastAPI:
    """Fabryka aplikacji - ulatwia testowanie i konfiguracje."""
    app = FastAPI(
        title="Phishing URL Detector",
        description="Analiza URL pod katem cech phishingowych: scoring, cechy, blacklist check.",
        version=__version__,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(router)

    # Serwowanie plikow statycznych (CSS itd.) spod /static
    app.mount("/static", StaticFiles(directory=_STATIC_DIR), name="static")

    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        """Serwuje formularz HTML (frontend) do testowania URL."""
        return FileResponse(_STATIC_DIR / "index.html")

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
