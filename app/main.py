"""FastAPI application entry point."""

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.config import configure_logging

configure_logging()

app = FastAPI(title="Mikrotik Whitelist Service", docs_url=None, redoc_url=None)

from app.routers import internal, ui  # noqa: E402 — after app is created

app.include_router(ui.router)
app.include_router(internal.router, prefix="/internal")
