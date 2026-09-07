from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from app.database import init_db
from app.auth import router as auth_router
from app.tickets import router as tickets_router
from app.security import RedirectToLoginException

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize DB tables and seed data
    init_db()
    yield

app = FastAPI(
    title="OpsDesk",
    description="Deliberately Vulnerable Lab for Secure Coding Demonstration",
    version="1.0.0",
    lifespan=lifespan
)

app.mount("/static", StaticFiles(directory="static"), name="static")

@app.exception_handler(RedirectToLoginException)
async def redirect_to_login_handler(request: Request, exc: RedirectToLoginException):
    return RedirectResponse(url="/login", status_code=303)

# Include Routers
app.include_router(auth_router)
app.include_router(tickets_router)

@app.get("/")
def root():
    return RedirectResponse(url="/dashboard")
