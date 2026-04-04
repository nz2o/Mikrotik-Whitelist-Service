import logging
import os
import sys

from dotenv import load_dotenv

load_dotenv()


def _require(var: str) -> str:
    val = os.getenv(var)
    if not val:
        raise RuntimeError(f"Required environment variable '{var}' is not set.")
    return val


POSTGRES_USER = _require("POSTGRES_USER")
POSTGRES_PASSWORD = _require("POSTGRES_PASSWORD")
POSTGRES_HOST = os.getenv("POSTGRES_HOST", "postgres")
POSTGRES_PORT = os.getenv("POSTGRES_PORT", "5432")
POSTGRES_DATABASE = _require("POSTGRES_DATABASE")

DATABASE_URL = (
    f"postgresql+psycopg2://{POSTGRES_USER}:{POSTGRES_PASSWORD}"
    f"@{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DATABASE}"
)

ENCRYPTION_KEY = _require("ENCRYPTION_KEY")

FETCH_TIMEOUT_SECONDS = int(os.getenv("FETCH_TIMEOUT_SECONDS", "30"))
FETCH_RETRIES = int(os.getenv("FETCH_RETRIES", "3"))
APPLY_TIMEOUT_SECONDS = int(os.getenv("APPLY_TIMEOUT_SECONDS", "60"))

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
RAWIPLISTS_DIR = os.getenv("RAWIPLISTS_DIR", "/app/data/rawiplists")


def configure_logging():
    from pythonjsonlogger import jsonlogger

    handler = logging.StreamHandler(sys.stdout)
    formatter = jsonlogger.JsonFormatter(
        fmt="%(asctime)s %(levelname)s %(name)s %(message)s"
    )
    handler.setFormatter(formatter)

    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))
