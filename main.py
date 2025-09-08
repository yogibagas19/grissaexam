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
SESSION_TIMEOUT_SECONDS = 900
redis_client = redis.Redis(host='redis', port=6379, db=0, decode_responses=True)

def generate_new_token():
    return "".join(random.choices(string.digits, k=6))

def refresh_tokens_job():
    db = SessionLocal()
    try:
        app_state = db.query(AppState).filter(AppState.id == 1).first()
        # --- TAMBAHKAN BLOK 'IF' INI ---
        if not app_state:
            app_state = AppState(id=1)
            db.add(app_state)
            db.commit()
            db.refresh(app_state)
            
        new_admin_token = generate_new_token()
        app_state.current_token = new_admin_token
        redis_client.set("current_admin_token", new_admin_token)
        print(f"Token Admin Baru (Otomatis): {new_admin_token}")

        new_reentry_token = generate_new_token()
        if hasattr(app_state, 'reentry_token'):
            app_state.reentry_token = new_reentry_token # Asumsi Anda sudah menambahkan kolom 'reentry_token' di model AppState
        redis_client.set("current_reentry_token", new_reentry_token)
        print(f"Token Re-entry Baru (Otomatis): {new_reentry_token}")

        db.commit()
    finally:
        db.close()

scheduler = AsyncIOScheduler()
scheduler.add_job(refresh_tokens_job, "interval", minutes=30)

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("Memulai aplikasi dan mengisi cache token awal...")
    refresh_tokens_job()
    
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

class SessionRequest(BaseModel):
    sessionId: str


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
    return templates.TemplateResponse("index.html", {"request": request, "title": "DISAPA"})

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

@app.post("/api/v2/validate-token", tags=["API"])
async def validate_token(request: TokenValidationRequest):
    # =================================================================
    # SKENARIO 1: PERMINTAAN RE-ENTRY (ADA SESSION ID)
    # =================================================================
    if request.sessionId:
        print(f"Menerima permintaan RE-ENTRY untuk sesi: {request.sessionId}")
        
        # 1. Ambil token re-entry yang sedang aktif dari cache
        active_reentry_token = redis_client.get("current_reentry_token")
        
        # 2. Cek apakah token yang diberikan siswa BENAR
        if not active_reentry_token or request.token != active_reentry_token:
            print(f"Validasi GAGAL: Token re-entry salah. Diberikan: '{request.token}', Diharapkan: '{active_reentry_token}'")
            return {"isValid": False}

        # 3. Cek apakah device ini SUDAH PERNAH menggunakan token aktif ini
        # Kita buat kunci unik di Redis untuk melacak penggunaan token ini
        usage_key = f"used_reentry_token:{active_reentry_token}"
        if redis_client.sismember(usage_key, request.sessionId):
            print(f"Validasi GAGAL: Sesi {request.sessionId} sudah pernah menggunakan token '{active_reentry_token}'.")
            return {"isValid": False}

        # 4. Jika semua pengecekan lolos, token valid. CATAT PENGGUNAANNYA.
        print(f"Validasi re-entry BERHASIL untuk sesi {request.sessionId}.")
        # Tambahkan ID sesi ke dalam set token yang telah digunakan
        redis_client.sadd(usage_key, request.sessionId)
        # Atur masa berlaku untuk data penggunaan ini agar tidak menumpuk selamanya
        # (sedikit lebih lama dari interval refresh token, misal 35 menit)
        redis_client.expire(usage_key, 2100) 
        
        return {"isValid": True}
        
    # =================================================================
    # SKENARIO 2: PERMINTAAN MASUK/KELUAR BIASA (TIDAK ADA SESSION ID)
    # =================================================================
    else:
        print("Menerima permintaan MASUK/KELUAR biasa.")
        expected_token = redis_client.get("current_admin_token")
        
        if expected_token and request.token == expected_token:
            print("Validasi Token Admin BERHASIL.")
            return {"isValid": True}
        else:
            print(f"Validasi Token Admin GAGAL. Diberikan: '{request.token}', Diharapkan: '{expected_token}'")
            return {"isValid": False}


class SessionIdRequest(BaseModel):
    sessionId: str

@app.get("/api/current-reentry-token", tags=["API"], dependencies=[Depends(get_current_admin)])
async def get_current_reentry_token():
    reentry_token = redis_client.get("current_reentry_token")
    return {"reentry_token": reentry_token}

@app.post("/api/refresh-reentry-token", tags=["API"], dependencies=[Depends(get_current_admin)])
async def refresh_reentry_token_manual(db: Session = Depends(get_db)):
    app_state = db.query(AppState).filter(AppState.id == 1).first()
    if not app_state:
        # Buat state jika belum ada
        app_state = AppState(id=1)
        db.add(app_state)
    
    new_reentry_token = generate_new_token()
    app_state.reentry_token = new_reentry_token
    redis_client.set("current_reentry_token", new_reentry_token)
    db.commit()
    
    print(f"Token Re-entry di-refresh manual: {new_reentry_token}")
    return {"reentry_token": new_reentry_token}

@app.post("/api/sessions/start", tags=["API"])
async def start_session_ttl(request: SessionRequest):
    session_id = request.sessionId
    if not session_id:
        raise HTTPException(status_code=400, detail="sessionId is required")
    session_key = f"active_session:{session_id}"
    redis_client.set(session_key, "active", ex=SESSION_TIMEOUT_SECONDS)
    print(f"Sesi dimulai: {session_id}, akan kedaluwarsa dalam {SESSION_TIMEOUT_SECONDS} detik.")
    return {"status": "session registered", "expires_in": SESSION_TIMEOUT_SECONDS}

@app.get("/api/active-sessions", tags=["API"], dependencies=[Depends(get_current_admin)])
async def get_active_sessions_ttl():
    session_keys = redis_client.scan_iter("active_session:*")
    active_sessions = [key.split(":", 1)[1] for key in session_keys]
    print(f"Mengambil daftar sesi aktif, ditemukan: {len(active_sessions)} sesi.")
    return {"active_sessions": active_sessions}

@app.post("/api/sessions/end", tags=["API"])
async def end_session_ttl(request: SessionRequest):
    session_id = request.sessionId
    if not session_id:
        raise HTTPException(status_code=400, detail="sessionId is required")
    session_key = f"active_session:{session_id}"
    redis_client.delete(session_key)
    print(f"Sesi diakhiri secara normal: {session_id}")
    return {"status": "session ended"}

@app.post("/api/sessions/heartbeat", tags=["Sesi"])
async def session_heartbeat(request: SessionRequest):
    session_id = request.sessionId
    if not session_id:
        raise HTTPException(status_code=400, detail="sessionId is required")
    session_key = f"active_session:{session_id}"
    if redis_client.exists(session_key):
        redis_client.expire(session_key, SESSION_TIMEOUT_SECONDS)
        print(f"Heartbeat diterima untuk sesi: {session_id}")
        return {"status": "heartbeat ok"}
    else:
        print(f"Heartbeat ditolak, sesi sudah kedaluwarsa: {session_id}")
        raise HTTPException(status_code=404, detail="Session not found or has expired.")