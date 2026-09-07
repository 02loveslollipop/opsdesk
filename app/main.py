import logging
import uuid
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware
from app.config import settings
from app.database import init_db
from app.auth import router as auth_router
from app.tickets import router as tickets_router
from app.admin import router as admin_router
from app.security import RedirectToLoginException

# Configure security auditing logger
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
)
logger = logging.getLogger("opsdesk.security")

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing OpsDesk database and security subsystems...")
    init_db()
    logger.info("OpsDesk service initialized in %s mode.", settings.ENVIRONMENT)
    yield
    logger.info("OpsDesk service shutting down.")

app = FastAPI(
    title="OpsDesk (Hardened)",
    description="Secure Coding Lab - Hardened Production Baseline",
    version="1.0.0",
    lifespan=lifespan,
    docs_url=None, # Disable public OpenAPI docs in hardened baseline
    redoc_url=None,
)

# -----------------------------------------------------------------------------
# Security Middleware: Defensive HTTP Headers
# -----------------------------------------------------------------------------
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        # Defense against clickjacking, MIME sniffing, and XSS
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=(), payment=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'self'; form-action 'self';"
        )
        # Suppress information disclosure headers
        if "server" in response.headers:
            del response.headers["server"]
        return response

# -----------------------------------------------------------------------------
# Security Middleware: Request Size Limiting (DoS mitigation)
# -----------------------------------------------------------------------------
class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > settings.MAX_REQUEST_SIZE_BYTES:
            logger.warning(
                "Request payload size (%s bytes) exceeded limit (%s bytes) from IP %s",
                content_length,
                settings.MAX_REQUEST_SIZE_BYTES,
                request.client.host if request.client else "unknown",
            )
            return JSONResponse(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                content={"detail": "Request payload exceeds permissible limit (1MB)."},
            )
        return await call_next(request)

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestSizeLimitMiddleware)

# Static file serving
app.mount("/static", StaticFiles(directory="static"), name="static")

# Exception Handlers
@app.exception_handler(RedirectToLoginException)
async def redirect_to_login_handler(request: Request, exc: RedirectToLoginException):
    return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    error_id = str(uuid.uuid4())
    logger.exception("Internal error captured (Ref ID: %s): %s", error_id, exc)
    
    is_json = "application/json" in request.headers.get("accept", "")
    if is_json:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": f"An internal system error occurred. Reference ID: {error_id}"}
        )
    return HTMLResponse(
        content=f"""
        <!DOCTYPE html>
        <html>
        <head><title>System Error - OpsDesk</title><link rel="stylesheet" href="/static/style.css"></head>
        <body style="display:flex;align-items:center;justify-content:center;height:100vh;">
            <div class="card" style="max-width:500px;text-align:center;">
                <h2 style="color:var(--accent-red);margin-bottom:1rem;">Internal Error</h2>
                <p style="color:var(--text-secondary);margin-bottom:1.5rem;">An error occurred while processing your request. Please contact administrator with reference ID: <code>{error_id}</code></p>
                <a href="/" class="btn btn-primary">Return to Home</a>
            </div>
        </body>
        </html>
        """,
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
    )

# Healthcheck endpoint
@app.get("/health")
def healthcheck():
    return {"status": "healthy", "mode": "hardened"}

# Include Routers
app.include_router(auth_router)
app.include_router(tickets_router)
app.include_router(admin_router)

@app.get("/")
def root():
    return RedirectResponse(url="/dashboard")
