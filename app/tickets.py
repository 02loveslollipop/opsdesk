import json
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import Ticket
from app.security import get_current_user

router = APIRouter()
templates = Jinja2Templates(directory="templates")

@router.get("/dashboard", response_class=HTMLResponse)
def dashboard_view(
    request: Request,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    tickets = db.query(Ticket).all()
    # Format claims nicely for presentation inspector
    token_claims_str = json.dumps(current_user, indent=2, default=str)
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "user": current_user,
            "tickets": tickets,
            "token_claims": token_claims_str,
        },
    )

@router.get("/tickets", response_class=HTMLResponse)
def tickets_view(
    request: Request,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    tickets = db.query(Ticket).all()
    return templates.TemplateResponse(
        "tickets.html",
        {
            "request": request,
            "user": current_user,
            "tickets": tickets,
        },
    )

@router.get("/profile")
def profile_view(
    request: Request,
    current_user: dict = Depends(get_current_user),
):
    # Returns profile info or renders in template
    if "text/html" in request.headers.get("accept", ""):
        return templates.TemplateResponse(
            "dashboard.html",
            {"request": request, "user": current_user, "tickets": []},
        )
    return {
        "status": "success",
        "user": current_user,
    }
