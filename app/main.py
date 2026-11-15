# ============================================================
# app/main.py — FastAPI Application Entry Point
# ============================================================
import logging
from contextlib import asynccontextmanager
from pathlib import Path
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse

from app.config import get_settings
from app.database import connect_db, close_db
from app.routes import (
    auth, dashboard, documents, analysis, privacy_gateway, reports, rag, analytics,
)

# ── Logging ───────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# ── Paths ─────────────────────────────────────────────────────
BASE_DIR     = Path(__file__).parent.parent   # sensitive-data-detection/
FRONTEND_DIR = BASE_DIR / "frontend"
CSS_DIR      = FRONTEND_DIR / "css"
JS_DIR       = FRONTEND_DIR / "js"


# ── Lifespan: startup / shutdown ──────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting Sensitive Data Detection API …")
    settings = get_settings()

    if settings.is_production and settings.secret_key == "change-this-secret-key":
        raise RuntimeError(
            "Refusing to start in production with the default SECRET_KEY. "
            "Set SECRET_KEY to a long random value."
        )
    if settings.is_production and not settings.pseudonym_key:
        logger.warning(
            "PSEUDONYM_KEY is unset; pseudonym mappings will use SECRET_KEY. "
            "Set a dedicated PSEUDONYM_KEY for production."
        )
    if settings.is_production and "*" in settings.cors_origin_list:
        logger.warning("CORS is open to all origins. Set CORS_ORIGINS in production.")

    connect_db()
    os.makedirs(settings.upload_dir, exist_ok=True)
    yield
    logger.info("Shutting down …")
    close_db()


# ── FastAPI app ───────────────────────────────────────────────
app = FastAPI(
    title="AI-Based Sensitive Data Detection and Privacy Classification System",
    description=(
        "Detect, classify, and sanitize sensitive information in documents "
        "before sharing with external AI services or cloud platforms."
    ),
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# ── CORS ──────────────────────────────────────────────────────
_settings = get_settings()
_origins = _settings.cors_origin_list
app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,
    # The wildcard cannot be combined with credentialed requests.
    allow_credentials=_origins != ["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── API Routers ───────────────────────────────────────────────
app.include_router(auth.router)
app.include_router(dashboard.router)
app.include_router(documents.router)
app.include_router(analysis.router)
app.include_router(privacy_gateway.router)
app.include_router(reports.router)
app.include_router(rag.router)
app.include_router(analytics.router)
app.include_router(analytics.admin_router)

# ── Health check ──────────────────────────────────────────────
@app.get("/api/health", tags=["Health"])
async def health():
    from app.database import get_db
    from app.services.detection_engine import nlp_is_available

    settings = get_settings()
    try:
        get_db().command("ping")
        database = "ok"
    except Exception:
        database = "unreachable"

    return {
        "status":              "ok" if database == "ok" else "degraded",
        "database":            database,
        "nlp_available":       nlp_is_available(),
        "external_ai_enabled": settings.external_ai_enabled,
        "environment":         settings.app_env,
        "version":             "1.0.0",
    }


# ── Serve frontend static files ────────────────────────────────
if CSS_DIR.exists():
    app.mount("/css", StaticFiles(directory=str(CSS_DIR)), name="css")
    logger.info("Serving CSS from: %s", CSS_DIR)

if JS_DIR.exists():
    app.mount("/js",  StaticFiles(directory=str(JS_DIR)),  name="js")
    logger.info("Serving JS from: %s", JS_DIR)


# ── Serve HTML pages ──────────────────────────────────────────
HTML_PAGES = [
    "index", "login", "register", "dashboard", "upload",
    "documents", "analysis", "history", "privacy-gateway",
    "reports", "profile", "rag",
]

if FRONTEND_DIR.exists():
    @app.get("/", include_in_schema=False)
    async def root():
        return FileResponse(str(FRONTEND_DIR / "index.html"))

    for _page in HTML_PAGES:
        _html_path = FRONTEND_DIR / f"{_page}.html"

        # Closure to capture current _html_path correctly
        def _make_handler(path: Path):
            async def _handler():
                if path.exists():
                    return FileResponse(str(path))
                return JSONResponse({"detail": "Page not found"}, status_code=404)
            return _handler

        app.add_api_route(
            f"/{_page}.html",
            _make_handler(_html_path),
            methods=["GET"],
            include_in_schema=False,
        )
else:
    @app.get("/", include_in_schema=False)
    async def root_fallback():
        return JSONResponse({
            "message": "Frontend not found. Place HTML files in the /frontend directory.",
            "docs":    "/docs",
        })
