import logging
from typing import Optional
from fastapi import APIRouter, Depends, Form, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import text
from sqlalchemy.orm import Session
from app.database import get_db

logger = logging.getLogger(__name__)

router = APIRouter()
templates = Jinja2Templates(directory="templates")

def authenticate_user_vulnerable(db: Session, username: str, password: str) -> Optional[dict]:
    """
    VULNERABLE LOGIN IMPLEMENTATION (Pedagogical demonstration of SQL Injection)
    
    The user inputs 'username' and 'password' are directly interpolated into the raw
    SQL query string using Python f-strings. This allows an attacker to break out of
    the intended SQL structure using metacharacters like single quotes (') and SQL comments (--).
    
    Exploit Example:
      username: admin' --
      password: (anything)
      Resulting SQL:
        SELECT id, username, password, role FROM users WHERE username = 'admin' --' AND password = '...'
    """
    raw_query = f"SELECT id, username, password, role FROM users WHERE username = '{username}' AND password = '{password}'"
    logger.info("Executing vulnerable SQL query: %s", raw_query)
    
    try:
        result = db.execute(text(raw_query)).fetchone()
        if result:
            return {
                "id": result[0],
                "username": result[1],
                "role": result[3]
            }
        return None
    except Exception as exc:
        logger.error("Database query execution error: %s", exc)
        return None

# By default, use vulnerable authentication in 01-vulnerable
authenticate_user = authenticate_user_vulnerable

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
