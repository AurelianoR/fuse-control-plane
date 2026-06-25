from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from web.config import get_settings
from web.db import init_db
from web.routers.grants import router as grants_router
from web.routers.runs import router as runs_router
from web.routers.tenants import router as tenants_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    if not settings.secret_encryption_key:
        raise RuntimeError(
            "SECRET_ENCRYPTION_KEY is not set. "
            "Generate one with: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
        )
    init_db(settings.database_url)
    yield


app = FastAPI(title="Fuse", lifespan=lifespan)

app.add_middleware(
    SessionMiddleware,
    secret_key=get_settings().secret_key,
    session_cookie="fuse_session",
    https_only=False,  # set to True in production behind TLS
)

app.mount(
    "/static",
    StaticFiles(directory=str(Path(__file__).parent / "static")),
    name="static",
)

app.include_router(tenants_router)
app.include_router(runs_router)
app.include_router(grants_router)


@app.get("/")
async def root():
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="/tenants")
