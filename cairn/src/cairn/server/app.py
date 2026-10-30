from contextlib import asynccontextmanager
import os
from pathlib import Path
import secrets

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from cairn import __version__
from cairn.server import db
from cairn.server.routers import export, facts, hints, intelligence, intents, projects, runs, settings

STATIC_DIR = Path(__file__).parent / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.configure(db.DEFAULT_DB)
    yield


app = FastAPI(
    title="Cairn",
    description="Fact-graph based collaborative exploration protocol",
    version=__version__,
    lifespan=lifespan,
)

app.include_router(settings.router)
app.include_router(projects.router)
app.include_router(hints.router)
app.include_router(intents.router)
app.include_router(facts.router)
app.include_router(intelligence.router)
app.include_router(export.router)
app.include_router(runs.router)


@app.middleware("http")
async def require_api_token(request: Request, call_next):
    expected = os.environ.get("CAIRN_API_TOKEN", "").strip()
    public_path = request.url.path == "/" or request.url.path == "/health" or request.url.path.startswith("/static/")
    if expected and not public_path:
        authorization = request.headers.get("authorization", "")
        scheme, _, supplied = authorization.partition(" ")
        if scheme.lower() != "bearer" or not secrets.compare_digest(supplied, expected):
            return JSONResponse(
                status_code=401,
                content={"detail": "Missing or invalid Cairn API token"},
                headers={"WWW-Authenticate": "Bearer"},
            )
    return await call_next(request)


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/health", include_in_schema=False)
def health():
    return {"status": "ok"}


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
