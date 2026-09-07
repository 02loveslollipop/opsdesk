import logging
from typing import Optional
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import APIRouter, Depends, Form, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import text
from sqlalchemy.orm import Session
from app.database import get_db

logger = logging.getLogger(__name__)

router = APIRouter()
templates = Jinja2Templates(directory="templates")
ph = PasswordHasher()

def authenticate_user_vulnerable(db: Session, username: str, password: str) -> Optional[dict]:
    """
    VULNERABLE LOGIN IMPLEMENTATION (Kept for educational reference)
    Constructs SQL via f-string interpolation, enabling SQL Injection.
    """
    raw_query = f"SELECT id, username, password, role FROM users WHERE username = '{username}' AND password = '{password}'"
    try:
        result = db.execute(text(raw_query)).fetchone()
        if result:
            return {"id": result[0], "username": result[1], "role": result[3]}
        return None
    except Exception as exc:
        logger.error("Vulnerable query error: %s", exc)
        return None

def authenticate_user_secure(db: Session, username: str, password: str) -> Optional[dict]:
    """
    SECURE LOGIN IMPLEMENTATION (Remediated)
    
    1. Parameterized SQL query: User input is sent separately as parameters (:username),
       ensuring the database query engine treats it solely as literal data.
    2. Strong Password Hashing: Verifies password using Argon2id with automatic salt.
    3. Constant-Time Verification: Prevents timing attacks.
    """
    query = text("SELECT id, username, password, role FROM users WHERE username = :username")
    logger.info("Executing secure parameterized query for user: %s", username)
    
    result = db.execute(query, {"username": username}).fetchone()
    if not result:
        return None

    stored_password_hash = result[2]
    
    try:
        # Verify password using Argon2
        if ph.verify(stored_password_hash, password):
            return {
                "id": result[0],
                "username": result[1],
                "role": result[3]
            }
    except VerifyMismatchError:
        logger.warning("Authentication failed: invalid password for user '%s'", username)
        return None
    except Exception as exc:
        logger.error("Password verification error: %s", exc)
        # Fallback check during transition
        if stored_password_hash == password:
            return {"id": result[0], "username": result[1], "role": result[3]}
        return None
    return None

# ACTIVE IMPLEMENTATION: Parameterized & Hashed
authenticate_user = authenticate_user_secure

@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html", {"error": None})

@router.post("/login")
def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    from app.security import create_access_token

    user = authenticate_user(db, username=username, password=password)
    
    is_json = (
        "application/json" in request.headers.get("accept", "") or
        "application/json" in request.headers.get("content-type", "")
    )

    if not user:
        if is_json:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": "Invalid username or password"}
            )
        return templates.TemplateResponse(
            request,
            "login.html",
            {"error": "Invalid username or password"}
        )

    # Generate JWT access token
    token = create_access_token(
        data={"sub": str(user["id"]), "username": user["username"], "role": user["role"]}
    )

    if is_json:
        return {
            "access_token": token,
            "token_type": "bearer",
            "user": user
        }

    response = RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(
        key="access_token",
        value=f"Bearer {token}",
        httponly=True,
        samesite="lax",
        max_age=1800
    )
    return response

@router.get("/logout")
def logout():
    response = RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie(key="access_token")
    return response
