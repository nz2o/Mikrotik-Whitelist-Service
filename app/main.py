"""FastAPI application entry point."""

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.config import configure_logging
from app.services import applicator as applicator_svc

configure_logging()

app = FastAPI(title="Mikrotik Whitelist Service", docs_url=None, redoc_url=None)

from app.routers import internal, ui  # noqa: E402 — after app is created

app.include_router(ui.router)
app.include_router(internal.router, prefix="/internal")


@app.on_event("startup")
def reconcile_apply_history_on_startup() -> None:
	applicator_svc.reconcile_interrupted_applies(source="api-startup")
