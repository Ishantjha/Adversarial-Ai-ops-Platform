# src/api/app.py
# Main FastAPI application — ties everything together

import os
import sys
sys.path.insert(0, "C:\\Users\\ISHANT JHA\\aiops-platform")

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from src.utils.logger import setup_logger
from src.detectors.alert_engine import AlertEngine
from src.mitigation.mitigation_engine import MitigationEngine
from src.api import routes
from config.settings import settings

logger = setup_logger("app")

# ─────────────────────────────────────────
# STARTUP & SHUTDOWN
# ─────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Runs on startup — loads all models."""
    logger.info("Starting AIOps Platform API...")

    # Initialize engines
    alert_engine      = AlertEngine()
    mitigation_engine = MitigationEngine()

    # Inject into routes
    routes.init_engines(alert_engine, mitigation_engine)

    logger.info("All engines loaded and ready!")
    logger.info(f"API running at http://{settings.API_HOST}:{settings.API_PORT}")
    logger.info(f"Docs at http://{settings.API_HOST}:{settings.API_PORT}/docs")

    yield  # API is running

    logger.info("Shutting down AIOps Platform API...")


# ─────────────────────────────────────────
# CREATE APP
# ─────────────────────────────────────────

app = FastAPI(
    title       = "AIOps Platform API",
    description = "Adversarial Attack-Resilient AIOps Platform for Cloud & ML Systems",
    version     = settings.APP_VERSION,
    lifespan    = lifespan,
    docs_url    = "/docs",
    redoc_url   = "/redoc"
)

# Allow dashboard to call the API
app.add_middleware(
    CORSMiddleware,
    allow_origins     = ["*"],
    allow_credentials = True,
    allow_methods     = ["*"],
    allow_headers     = ["*"]
)

# Register all routes
app.include_router(routes.router, prefix="/api/v1")

# ─────────────────────────────────────────
# ROOT ENDPOINT
# ─────────────────────────────────────────

@app.get("/")
def root():
    return {
        "name":    "AIOps Platform",
        "version": settings.APP_VERSION,
        "status":  "running",
        "docs":    "/docs"
    }