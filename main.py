import io
import os
import json
import qrcode
import random
import string
import sqlite3
import uuid
from contextlib import asynccontextmanager
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from fastapi import FastAPI, Request, Form, Depends, HTTPException, WebSocket, Header
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
import asyncio
from pydantic import BaseModel
from fastapi.staticfiles import StaticFiles
from models import SessionLocal, engine, User, AppState
from sqlalchemy.orm import Session
from security import verify_password, get_password_hash
import redis
from typing import Optional
from urllib.parse import urlencode
from google.auth.transport import requests
from google.oauth2 import id_token
from dotenv import load_dotenv

load_dotenv()

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")

if not GOOGLE_CLIENT_ID:
    print("PERINGATAN: Variabel GOOGLE_CLIENT_ID tidak ditemukan di file .env. Verifikasi token akan gagal.")

current_admin_token = None

SESSION_COOKIE_NAME = "grissa_admin_session"
SESSION_TIMEOUT_SECONDS = 900
TOKEN_GRACE_PERIOD_SECONDS = 120
REDIS_CHANNEL_NAME = "token_updates_channel"
redis_client = redis.Redis(host='redis', port=6379, db=0, decode_responses=True)

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("Memulai aplikasi...")
    
    yield
    
    print("Aplikasi berhasil dimatikan.")


app = FastAPI(title="Exam Browser Backend", lifespan=lifespan)
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

class QRCodeRequest(BaseModel):
    url: str
    use_secure_app: bool = True

class TokenValidationRequest(BaseModel):
    token: str
    sessionId: Optional[str] = None

class SessionRequest(BaseModel):
    sessionId: str

class ManualTokenUpdateRequest(BaseModel):
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
    return templates.TemplateResponse("index.html", {"request": request, "title": "DISAPA"})

@app.get("/api/current-token", tags=["API"], dependencies=[Depends(get_current_admin)])
async def get_current_token(db: Session = Depends(get_db)): # Tambahkan dependency db
    app_state = db.query(AppState).filter(AppState.id == 1).first()
    if not app_state:
        # Jika tidak ada, return null atau token error
        return {"token": None}
    return {"token": app_state.current_token}   

@app.post("/api/set-token", tags=["API"], dependencies=[Depends(get_current_admin)])
async def set_token_manual(request: ManualTokenUpdateRequest, db: Session = Depends(get_db)):
    """Menerima dan mengatur SATU token global baru secara manual."""
    new_token = request.token
    
    # Validasi: Pastikan token adalah 4 digit angka
    if not (new_token and len(new_token) == 4 and new_token.isdigit()):
        raise HTTPException(status_code=400, detail="Token harus terdiri dari 4 digit angka.")

    # Simpan token lama untuk masa tenggang (grace period)
    old_token = redis_client.get("current_admin_token")
    if old_token:
        redis_client.set("previous_admin_token", old_token, ex=TOKEN_GRACE_PERIOD_SECONDS)

    # Simpan token baru ke DB dan Redis
    app_state = db.query(AppState).filter(AppState.id == 1).first()
    if not app_state:
        app_state = AppState(id=1)
        db.add(app_state)
    app_state.current_token = new_token
    db.commit()
    redis_client.set("current_admin_token", new_token)
    
    # Siarkan pembaruan ke semua client via WebSocket
    update_message = {"type": "admin_token_update", "token": new_token}
    redis_client.publish(REDIS_CHANNEL_NAME, json.dumps(update_message))

    print(f"Token Global diatur manual menjadi: {new_token}")
    return {"status": "success", "token": new_token}

@app.post("/api/generate-qr", tags=["API"], dependencies=[Depends(get_current_admin)])
async def generate_qr_code(qr_request: QRCodeRequest, request: Request):
    
    url_to_encode = ""

    # Jika admin memilih untuk menggunakan aplikasi aman (pilihan default)
    if qr_request.use_secure_app:
        session_id = uuid.uuid4().hex
        base_url = str(request.base_url) 
        params = {
            "url": qr_request.url,
            "session": session_id
        }
        # Buat URL redirector yang akan membuka aplikasi
        url_to_encode = f"{base_url}exam/start?{urlencode(params)}"
        print(f"Membuat QR Code AMAN untuk URL: {url_to_encode}")

    # Jika admin memilih untuk menggunakan browser biasa
    else:
        # Langsung gunakan URL asli yang diinput (misal, link Google Form)
        url_to_encode = qr_request.url
        print(f"Membuat QR Code BIASA untuk URL: {url_to_encode}")

    # Buat gambar QR code dari URL yang telah ditentukan
    img = qrcode.make(url_to_encode)
    buffer = io.BytesIO()
    img.save(buffer, "PNG")
    buffer.seek(0)
    return StreamingResponse(buffer, media_type="image/png")

@app.websocket("/ws/token-updates")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    
    pubsub = redis_client.pubsub()
    pubsub.subscribe(REDIS_CHANNEL_NAME)
    
    print("Client baru terhubung dan subscribe ke channel Redis.")

    try:
        admin_token = redis_client.get("current_admin_token")
        initial_data = {"type": "initial_state", "admin_token": admin_token}
        await websocket.send_text(json.dumps(initial_data))
    except Exception as e:
        print(f"Error saat mengirim initial state ke client: {e}")

    async def redis_listener(ws: WebSocket, ps: redis.client.PubSub):
        try:
            while True:
                message = ps.get_message(ignore_subscribe_messages=True, timeout=1.0)
                if message and message["type"] == "message":
                    await ws.send_text(message['data'])
                await asyncio.sleep(0.01)
        except Exception:
            pass

    async def client_listener(ws: WebSocket):
        try:
            while True:
                await ws.receive_text()
        except Exception:
            pass

    listener_tasks = [
        asyncio.create_task(redis_listener(websocket, pubsub)),
        asyncio.create_task(client_listener(websocket))
    ]
    
    done, pending = await asyncio.wait(listener_tasks, return_when=asyncio.FIRST_COMPLETED)
    
    for task in pending:
        task.cancel()
    
    pubsub.unsubscribe(REDIS_CHANNEL_NAME)
    pubsub.close()
    print("Client terputus, koneksi Pub/Sub ditutup.")

@app.post("/api/v2/validate-token", tags=["API"])
async def validate_token(request: TokenValidationRequest):
    """Memvalidasi SEMUA token terhadap satu token global."""
    token_to_validate = request.token
    
    current_token = redis_client.get("current_admin_token")
    previous_token = redis_client.get("previous_admin_token")

    if (current_token and token_to_validate == current_token) or \
       (previous_token and token_to_validate == previous_token):
        return {"isValid": True}
    else:
        return {"isValid": False}

@app.get("/exam/start", response_class=RedirectResponse, tags=["Deep Link"])
async def start_exam_redirect(url: str, session: str):
    """
    Endpoint ini dibuka oleh browser setelah scan QR.
    Tugasnya adalah mengalihkan (redirect) ke custom URL scheme aplikasi Android.
    """
    # Membuat custom URL scheme, contoh: grissaexam://start?url=...&session=...
    params = urlencode({"url": url, "session": session})
    custom_scheme_url = f"grissaexam://start?{params}"
    
    # Memberitahu browser untuk mencoba membuka link aplikasi
    return RedirectResponse(url=custom_scheme_url)

class SessionIdRequest(BaseModel):
    sessionId: str


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

@app.get("/api/auth/callback", response_class=RedirectResponse, tags=["Authentication"])
async def auth_callback(request: Request):
    """
    Menerima redirect dari Google setelah login berhasil,
    lalu meneruskannya ke aplikasi Android menggunakan custom scheme.
    """
    # Cukup alihkan ke skema kustom yang akan ditangkap oleh aplikasi
    return RedirectResponse(url="grissaexam://auth-callback")  