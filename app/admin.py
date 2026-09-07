from fastapi import APIRouter, Depends, Form, Request, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import User
from app.security import get_current_user, require_admin
from app.diagnostics import run_diagnostics

router = APIRouter(prefix="/admin")
templates = Jinja2Templates(directory="templates")

@router.get("", response_class=HTMLResponse)
def admin_panel_view(
    request: Request,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    require_admin(current_user)
    users = db.query(User).all()
    return templates.TemplateResponse(
        "admin.html",
        {
            "request": request,
            "user": current_user,
            "users": users,
        },
    )

@router.get("/users")
def admin_users_view(
    request: Request,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    require_admin(current_user)
    users = db.query(User).all()
    user_list = [{"id": u.id, "username": u.username, "role": u.role} for u in users]
    
    if "text/html" in request.headers.get("accept", ""):
        return templates.TemplateResponse(
            "admin.html",
            {"request": request, "user": current_user, "users": users},
        )
    return {"users": user_list}

@router.get("/diagnostics", response_class=HTMLResponse)
def admin_diagnostics_page(
    request: Request,
    current_user: dict = Depends(get_current_user),
):
    require_admin(current_user)
    return templates.TemplateResponse(
        "diagnostics.html",
        {
            "request": request,
            "user": current_user,
            "output": None,
            "host": "127.0.0.1",
            "error": None,
        },
    )

@router.post("/diagnostics")
def admin_diagnostics_run(
    request: Request,
    host: str = Form(...),
    current_user: dict = Depends(get_current_user),
):
    require_admin(current_user)
    
    is_json = (
        "application/json" in request.headers.get("accept", "") or
        "application/json" in request.headers.get("content-type", "")
    )

    try:
        output = run_diagnostics(host)
    except ValueError as val_err:
        if is_json:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"detail": str(val_err)}
            )
        return templates.TemplateResponse(
            "diagnostics.html",
            {
                "request": request,
                "user": current_user,
                "output": None,
                "host": host,
                "error": str(val_err),
            },
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    if is_json:
        return {"host": host, "output": output}

    return templates.TemplateResponse(
        "diagnostics.html",
        {
            "request": request,
            "user": current_user,
            "output": output,
            "host": host,
            "error": None,
        },
    )
