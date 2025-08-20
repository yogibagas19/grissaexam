import io
import json
import qrcode
import random
import string
import sqlite3
import uuid
from contextlib import asynccontextmanager
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from fastapi import FastAPI, Request, Form, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from passlib.context import CryptContext
from pydantic import BaseModel
from fastapi.staticfiles import StaticFiles
from models import SessionLocal, engine, User, AppState
from sqlalchemy.orm import Session
from security import verify_password, get_password_hash
import redis
from typing import Optional

current_admin_token = None
SESSION_COOKIE_NAME = "grissa_admin_session"
redis_client = redis.Redis(host='redis', port=6379, db=0, decode_responses=True)

def generate_new_token():
    return "".join(random.choices(string.digits, k=6))

def refresh_admin_token_job():
    db = SessionLocal()
    try:
        app_state = db.query(AppState).filter(AppState.id == 1).first()
        # --- TAMBAHKAN BLOK 'IF' INI ---
        if not app_state:
            app_state = AppState(id=1)
            db.add(app_state)
            db.commit()
            db.refresh(app_state)

        new_token = generate_new_token()
        app_state.current_token = new_token
        db.commit()

        redis_client.set("current_admin_token", new_token)
        print(f"Token Admin Baru (Otomatis & Disimpan di Cache): {new_token}")
    finally:
        db.close()

scheduler = AsyncIOScheduler()
scheduler.add_job(refresh_admin_token_job, "interval", minutes=30)

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("Memulai aplikasi dan mengisi cache token awal...")
    db = SessionLocal()
    try:
        app_state = db.query(AppState).filter(AppState.id == 1).first()
        # --- TAMBAHKAN BLOK 'IF' INI ---
        if not app_state:
            app_state = AppState(id=1)
            db.add(app_state)
            db.commit()
            db.refresh(app_state)

        new_token = generate_new_token()
        app_state.current_token = new_token
        db.commit()
        redis_client.set("current_admin_token", new_token)
        print(f"Token awal berhasil dibuat dan disimpan di cache: {new_token}")
    finally:
        db.close()
    
    scheduler.start()
    print("Scheduler berhasil dimulai.")
    
    yield
    
    print("Mematikan scheduler...")
    scheduler.shutdown()
    print("Aplikasi berhasil dimatikan.")

app = FastAPI(title="Exam Browser Backend", lifespan=lifespan)
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

class QRCodeRequest(BaseModel):
    url: str

class TokenValidationRequest(BaseModel):
    token: str
    sessionId: Optional[str] = None

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
async def get_current_token(db: Session = Depends(get_db)): # Tambahkan dependency db
    app_state = db.query(AppState).filter(AppState.id == 1).first()
    if not app_state:
        # Jika tidak ada, return null atau token error
        return {"token": None}
    return {"token": app_state.current_token}   

@app.post("/api/refresh-token", tags=["API"], dependencies=[Depends(get_current_admin)])
async def refresh_token_manual(db: Session = Depends(get_db)):
    app_state = db.query(AppState).filter(AppState.id == 1).first()
    # --- TAMBAHKAN BLOK 'IF' INI ---
    if not app_state:
        app_state = AppState(id=1)
        db.add(app_state)
        db.commit()
        db.refresh(app_state)
    
    new_token = generate_new_token()
    app_state.current_token = new_token
    db.commit()
    redis_client.set("current_admin_token", new_token)
    return {"token": new_token}

@app.post("/api/generate-qr", tags=["API"], dependencies=[Depends(get_current_admin)])
async def generate_qr_code(qr_request: QRCodeRequest):
    session_id = uuid.uuid4().hex
    data_to_encode = {
        "exam_url": qr_request.url, 
        "exam_session_id": session_id
    }
    json_string = json.dumps(data_to_encode)
    img = qrcode.make(json_string)
    buffer = io.BytesIO()
    img.save(buffer, "PNG")
    buffer.seek(0)
    return StreamingResponse(buffer, media_type="image/png")

# @app.post("/api/validate-token", tags=["API"])
# async def validate_token(request: TokenValidationRequest):
#     cached_token = redis_client.get("current_admin_token")

#     if request.token and request.token == cached_token:
#         return {"isValid": True}
#     return {"isValid": False}
@app.post("/api/validate-token", tags=["API"])
async def validate_token(request: TokenValidationRequest):
    # Skenario 2: Permintaan Re-entry (dari layar terkunci)
    if request.sessionId:
        print(f"Menerima permintaan re-entry untuk sesi: {request.sessionId}")
        expected_token = redis_client.get(f"reentry_token_for:{request.sessionId}")
        
        if expected_token and request.token == expected_token:
            redis_client.delete(f"reentry_token_for:{request.sessionId}")
            return {"isValid": True}
        else:
            return {"isValid": False}
            
    # Skenario 1: Permintaan Keluar Biasa (dari tombol Exit)
    else:
        print("Menerima permintaan keluar biasa.")
        cached_token = redis_client.get("current_admin_token")
        if request.token and request.token == cached_token:
            return {"isValid": True}
        else:
            return {"isValid": False}


class SessionIdRequest(BaseModel):
    sessionId: str

@app.post("/api/generate-reentry-token", tags=["API"], dependencies=[Depends(get_current_admin)])
async def generate_reentry_token(request: SessionIdRequest):
    new_reentry_token = generate_new_token()
    redis_client.set(f"reentry_token_for:{request.sessionId}", new_reentry_token, ex=300)
    print(f"Token Lanjutan untuk sesi {request.sessionId} adalah {new_reentry_token}")
    # Logika untuk menghasilkan re-entry token berdasarkan sessionId
    return {"reentry_token": new_reentry_token}

@app.post("/api/session/start", tags=["API"])
async def start_session(request: SessionIdRequest):
    session_id = request.sessionId
    if session_id:
        redis_client.sadd("active_exam_sessions", session_id)
        print(f"Sesi dimulai dan terdaftar: {session_id}")
        return {"status": "session regsitered"}
    return {"status": "error", "message": "sessionId is required"}

@app.get("/api/active-sessions", tags=["API"])
async def get_active_sessions():
    session_ids = redis_client.smembers("active_exam_sessions")
    return {"active_sessions": list(session_ids)}

@app.post("/api/session/end", tags=["API"])
async def end_session(request: SessionIdRequest):
    session_id = request.sessionId
    if session_id:
        redis_client.srem("active_exam_sessions", session_id)
        print(f"Sesi diakhiri dan dihapus dari daftar aktif: {session_id}")
        return {"status": "session ended"}
    return {"status": "error", "message": "sessionId is required"}