import io
import json
import qrcode
import random
import string
import sqlite3
from contextlib import asynccontextmanager
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from fastapi import FastAPI, Request, Form, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from passlib.context import CryptContext
from pydantic import BaseModel
from fastapi.staticfiles import StaticFiles
from sqladmin import Admin
from models import SessionLocal, engine, User
from sqlalchemy.orm import Session
from security import verify_password, get_password_hash

current_admin_token = None
SESSION_COOKIE_NAME = "grissa_admin_session"

def generate_new_token():
    return "".join(random.choices(string.digits, k=6))

def refresh_admin_token_job():
    global current_admin_token
    current_admin_token = generate_new_token()
    print(f"Token Admin Baru (Otomatis): {current_admin_token}")

scheduler = AsyncIOScheduler()
scheduler.add_job(refresh_admin_token_job, "interval", minutes=30)

@asynccontextmanager
async def lifespan(app: FastAPI):
    global current_admin_token
    current_admin_token = generate_new_token()
    scheduler.start()
    print("Server dimulai...")
    yield
    scheduler.shutdown()
    print("Server dimatikan...")

app = FastAPI(title="Exam Browser Backend", lifespan=lifespan)
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

class QRCodeRequest(BaseModel):
    url: str

class TokenValidationRequest(BaseModel):
    token: str

async def get_current_admin(request: Request):
    if not request.cookies.get(SESSION_COOKIE_NAME):
        raise HTTPException(status_code=307, headers={"Location": "/login"})

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login", response_class=RedirectResponse)
def handle_login(username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    
    if user and verify_password(password, user.hashed_password):
        response = RedirectResponse(url="/", status_code=303)
        response.set_cookie(key=SESSION_COOKIE_NAME, value="admin_logged_in", httponly=True)
        return response
    return RedirectResponse(url="/login?error=true", status_code=303)

@app.post("/logout", response_class=RedirectResponse)
async def logout(request: Request):
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie(SESSION_COOKIE_NAME)
    return response

@app.get("/admin/users", response_class=HTMLResponse, dependencies=[Depends(get_current_admin)])
async def list_users(request: Request, db: Session = Depends(get_db)):
    users = db.query(User).order_by(User.id).all()
    return templates.TemplateResponse("user_list.html", {"request": request, "users": users})

@app.get("/admin/users/create", response_class=HTMLResponse, dependencies=[Depends(get_current_admin)])
async def create_user_form(request: Request):
    return templates.TemplateResponse("user_form.html", {"request": request, "user": None})

@app.post("/admin/users/create", response_class=RedirectResponse, dependencies=[Depends(get_current_admin)])
async def create_user_handler(request: Request, db: Session = Depends(get_db)):
    form_data = await request.form()
    username = form_data.get("username")
    password = form_data.get("password")

    if not password:
        return templates.TemplateResponse("user_form.html", {"request": request, "user": None, "error": "Password wajib diisi untuk user baru."}, status_code=400)

    existing_user = db.query(User).filter(User.username == username).first()
    if existing_user:
        return templates.TemplateResponse("user_form.html", {"request": request, "user": None, "error": f"Username '{username}' sudah digunakan."}, status_code=400)

    hashed_password = get_password_hash(password)
    new_user = User(username=username, hashed_password=hashed_password)
    db.add(new_user)
    db.commit()
    return RedirectResponse(url="/admin/users", status_code=303)

@app.get("/admin/users/edit/{user_id}", response_class=HTMLResponse, dependencies=[Depends(get_current_admin)])
async def edit_user_form(request: Request, user_id: int, db: Session = Depends(get_db)):
    """Menampilkan form untuk mengedit user yang ada."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return templates.TemplateResponse("user_form.html", {"request": request, "user": user})

@app.post("/admin/users/edit/{user_id}", response_class=RedirectResponse, dependencies=[Depends(get_current_admin)])
async def edit_user_handler(request: Request, user_id: int, db: Session = Depends(get_db)):
    """Memproses data dari form edit user."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    form_data = await request.form()
    user.username = form_data.get("username")
    password = form_data.get("password")

    if password:
        user.hashed_password = get_password_hash(password)

    db.commit()
    return RedirectResponse(url="/admin/users", status_code=303)

@app.post("/admin/users/delete/{user_id}", response_class=RedirectResponse, dependencies=[Depends(get_current_admin)])
async def delete_user_handler(user_id: int, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    db.delete(user)
    db.commit()
    return RedirectResponse(url="/admin/users", status_code=303)

@app.get("/", response_class=HTMLResponse, dependencies=[Depends(get_current_admin)])
async def serve_teacher_dashboard(request: Request):
    return templates.TemplateResponse("index.html", {"request": request, "title": "Dashboard Admin"})

@app.get("/api/current-token", tags=["API"], dependencies=[Depends(get_current_admin)])
async def get_current_token():
    return {"token": current_admin_token}

@app.post("/api/refresh-token", tags=["API"], dependencies=[Depends(get_current_admin)])
async def refresh_token_manual():
    global current_admin_token
    current_admin_token = generate_new_token()
    return {"token": current_admin_token}

@app.post("/api/generate-qr", tags=["API"], dependencies=[Depends(get_current_admin)])
async def generate_qr_code(qr_request: QRCodeRequest):
    data_to_encode = {"exam_url": qr_request.url}
    json_string = json.dumps(data_to_encode)
    img = qrcode.make(json_string)
    buffer = io.BytesIO()
    img.save(buffer, "PNG")
    buffer.seek(0)
    return StreamingResponse(buffer, media_type="image/png")

@app.post("/api/validate-token", tags=["API"])
async def validate_token(request: TokenValidationRequest):
    if request.token and request.token == current_admin_token:
        return {"isValid": True}
    return {"isValid": False}