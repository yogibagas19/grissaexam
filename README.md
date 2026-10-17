# GrissaExam Backend (Proktor DISAPA)

Sistem backend dan dashboard proktor berbasis web untuk mendukung pelaksanaan ujian berbasis perangkat bergerak (Mobile Computer-Based Test) menggunakan aplikasi Exam Browser khusus (**GrissaExam**). Proyek ini dirancang untuk menyediakan sinkronisasi token secara real-time, pembuatan QR Code terenkapsulasi dengan mekanisme deep-linking ke aplikasi Android, serta pemantauan sesi peserta ujian secara langsung.

---

## Ringkasan Arsitektur dan Solusi Teknis

Pelaksanaan ujian daring menggunakan perangkat siswa sering menghadapi kendala kecurangan, keterlambatan distribusi token akses, serta sulitnya memantau perangkat yang masih aktif di dalam sesi ujian. **GrissaExam Backend** menyelesaikan permasalahan tersebut melalui pendekatan arsitektur berikut:

1. **Sinkronisasi Token Real-Time Berbasis Pub/Sub dan WebSocket**
   Perubahan token global yang dilakukan oleh proktor disimpan ke dalam basis data relasional (SQLite) untuk persistensi dan di-cache ke dalam Redis. Pembaruan tersebut langsung dipublikasikan melalui kanal Redis Pub/Sub (`token_updates_channel`) dan diteruskan ke seluruh klien yang terhubung melalui koneksi WebSocket (`/ws/token-updates`) tanpa memerlukan polling HTTP berulang.
2. **Mekanisme Masa Tenggang Token (Token Grace Period)**
   Saat proktor memperbarui token global (4 digit angka), sistem secara otomatis menyimpan token sebelumnya di Redis dengan batas waktu kedaluwarsa (TTL) selama 120 detik (`TOKEN_GRACE_PERIOD_SECONDS`). Pendekatan ini mencegah kegagalan validasi (race condition) bagi peserta ujian yang sedang berada di tengah proses autentikasi saat pergantian token terjadi.
3. **Pelacakan Sesi Berbasis TTL dan Heartbeat**
   Setiap sesi ujian yang dimulai diregistrasikan ke dalam Redis dengan kunci `active_session:<sessionId>` dan waktu hidup (TTL) selama 900 detik. Aplikasi klien mengirimkan sinyal *heartbeat* secara berkala untuk memperpanjang masa aktif sesi, sehingga sesi yang terputus secara tidak normal akan otomatis dibersihkan ketika TTL habis.
4. **Enkapsulasi URL melalui Deep Link Custom Scheme**
   Sistem menghasilkan kode QR dinamis yang mengarahkan perangkat peserta ke endpoint perantara (`/exam/start`). Endpoint ini membungkus URL ujian asli (seperti Google Form atau LMS) beserta UUID sesi unik ke dalam skema URI khusus (`grissaexam://start?url=...&session=...`), memastikan ujian hanya dapat dibuka melalui aplikasi GrissaExam di Android.

---

## Fitur Utama

* **Dashboard Proktor Terpusat**: Antarmuka web responsif untuk mengelola jalannya ujian, mengatur token, membuat QR Code, dan memantau sesi aktif.
* **Manajemen Token Global Real-Time**: Pengaturan token 4 digit untuk kontrol akses masuk, keluar, dan masuk kembali (*re-entry*) ke dalam aplikasi ujian.
* **Generator QR Code Multi-Mode**: Mendukung pembuatan kode QR untuk membuka ujian secara paksa di aplikasi aman GrissaExam maupun melalui peramban standar, dilengkapi fitur unduh gambar langsung (`.png`).
* **Pemantauan Sesi Aktif (Live Session Monitoring)**: Menampilkan daftar ID sesi perangkat yang sedang mengerjakan ujian beserta fitur pencarian instan untuk memudahkan pengawasan oleh proktor.
* **Jembatan Callback Autentikasi (OAuth Callback Bridge)**: Endpoint `/api/auth/callback` untuk meneruskan proses autentikasi eksternal (Google Auth) kembali ke dalam aplikasi Android melalui skema `grissaexam://auth-callback`.
* **Manajemen Akun Proktor (CRUD)**: Sistem autentikasi berbasis sesi *HTTP-Only Cookie* dengan pengamanan kata sandi menggunakan algoritma hashing `sha512_crypt` (Passlib), dilengkapi halaman administrasi untuk menambah, mengubah, dan menghapus akun proktor.

---

## Teknologi yang Digunakan

* **Bahasa Pemrograman**: Python 3.11
* **Web Framework**: FastAPI (Asynchronous REST API & WebSocket)
* **ASGI Server**: Gunicorn dengan Uvicorn Workers (`uvicorn.workers.UvicornWorker`)
* **In-Memory Data Store & Message Broker**: Redis (Caching, Session TTL, Pub/Sub)
* **Relational Database & ORM**: SQLite & SQLAlchemy 2.0
* **Template Engine & Frontend**: Jinja2, HTML5, CSS3, Vanilla JavaScript (WebSocket API & Fetch API)
* **Keamanan & Autentikasi**: Passlib (`sha512_crypt`), Google Auth Library, HTTP-Only Session Cookies
* **Utilitas Pemrosesan**: `qrcode` & `Pillow` (Pembuatan gambar QR Code di memori)
* **Infrastruktur & Deployment**: Docker & Docker Compose

---

## Struktur Proyek

```text
grissaexam/
├── static/
│   └── images/                 # Aset gambar statis (latar belakang dan logo institusi)
├── templates/
│   ├── index.html              # Dashboard utama proktor (Token, QR Generator, Monitoring Sesi)
│   ├── login.html              # Halaman autentikasi admin/proktor
│   ├── user_form.html          # Formulir tambah dan ubah data pengguna admin
│   └── user_list.html          # Tabel manajemen daftar pengguna admin
├── Dockerfile                  # Konfigurasi image kontainer aplikasi Python/FastAPI
├── docker-compose.yml          # Orkestrasi layanan aplikasi dan Redis beserta healthcheck
├── init_db.py                  # Skrip inisialisasi skema database dan pembuatan akun admin awal
├── main.py                     # Titik masuk aplikasi, definisi rute HTTP, API, dan WebSocket
├── models.py                   # Definisi model ORM SQLAlchemy (User dan AppState)
├── requirements.txt            # Daftar dependensi pustaka Python
└── security.py                 # Utilitas hashing dan verifikasi kata sandi
```

---

## Dokumentasi Endpoint API

### Autentikasi & Halaman Antarmuka (Web UI)

| Metode | Endpoint | Akses | Deskripsi |
| :--- | :--- | :--- | :--- |
| `GET` | `/login` | Publik | Menampilkan halaman login proktor. |
| `POST` | `/login` | Publik | Memverifikasi kredensial dan mengatur cookie sesi `grissa_admin_session`. |
| `POST` | `/logout` | Admin | Menghapus sesi login dan mengalihkan ke halaman login. |
| `GET` | `/` | Admin | Menampilkan dashboard utama Proktor DISAPA. |
| `GET` | `/admin/users` | Admin | Menampilkan daftar akun admin/proktor terdaftar. |
| `GET/POST` | `/admin/users/create` | Admin | Menampilkan form dan memproses pembuatan akun admin baru. |
| `GET/POST` | `/admin/users/edit/{user_id}` | Admin | Menampilkan form dan memproses perubahan data akun admin. |
| `POST` | `/admin/users/delete/{user_id}` | Admin | Menghapus akun admin berdasarkan ID. |

### Manajemen Token & QR Code (REST API)

| Metode | Endpoint | Akses | Deskripsi |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/current-token` | Admin | Mengambil nilai token global yang sedang aktif dari database. |
| `POST` | `/api/set-token` | Admin | Mengatur token 4 digit baru, menyimpan masa tenggang token lama di Redis, dan menyiarkan pembaruan via Pub/Sub. |
| `POST` | `/api/v2/validate-token` | Klien / Publik | Memvalidasi token yang dikirimkan aplikasi klien terhadap token aktif maupun token dalam masa tenggang. |
| `POST` | `/api/generate-qr` | Admin | Menghasilkan gambar QR Code berformat PNG berdasarkan URL ujian dan opsi penggunaan aplikasi aman. |

### Manajemen Sesi, Deep Link, & Real-Time

| Metode | Endpoint | Akses | Deskripsi |
| :--- | :--- | :--- | :--- |
| `WS` | `/ws/token-updates` | Klien / Admin | Koneksi WebSocket untuk menerima status token awal dan siaran perubahan token secara real-time. |
| `GET` | `/exam/start` | Klien / Publik | Mengalihkan hasil pindaian QR ke custom URI scheme `grissaexam://start?url=...&session=...`. |
| `GET` | `/api/auth/callback` | Klien / Publik | Mengalihkan callback autentikasi Google ke `grissaexam://auth-callback`. |
| `POST` | `/api/sessions/start` | Klien / Publik | Mendaftarkan sesi ujian baru ke Redis dengan TTL 900 detik. |
| `POST` | `/api/sessions/heartbeat` | Klien / Publik | Memperbarui waktu kedaluwarsa (TTL) sesi aktif di Redis. |
| `POST` | `/api/sessions/end` | Klien / Publik | Mengakhiri dan menghapus data sesi aktif dari Redis secara normal. |
| `GET` | `/api/active-sessions` | Admin | Mengambil seluruh daftar ID sesi yang masih aktif di Redis. |

---

## Panduan Instalasi dan Penggunaan

### Prasyarat

* **Docker** dan **Docker Compose** (Direkomendasikan untuk deployment)
* **Python 3.11+** dan **Redis Server** (Jika dijalankan secara lokal tanpa Docker)

### Variabel Lingkungan (Environment Variables)

Buat file `.env` pada direktori utama proyek dan sesuaikan konfigurasi berikut:

```env
GOOGLE_CLIENT_ID=your_google_oauth_client_id_here
```

### Menjalankan dengan Docker Compose (Direkomendasikan)

1. Kloning repositori ini ke mesin lokal atau server Anda:
   ```bash
   git clone <url-repositori-anda>
   cd grissaexam
   ```

2. Buat file database SQLite kosong (jika belum ada) agar volume mount Docker berjalan dengan baik, lalu bangun dan jalankan layanan:
   ```bash
   docker compose up -d --build
   ```

3. Inisialisasi skema database dan akun admin bawaan di dalam kontainer:
   ```bash
   docker compose exec app python init_db.py
   ```

4. Aplikasi dapat diakses melalui peramban pada alamat `http://localhost:8010`.

### Menjalankan Secara Lokal (Lingkungan Pengembangan)

1. Pastikan layanan **Redis** sudah berjalan pada host yang sesuai (secara bawaan kode menghubungkan ke host `redis` pada port `6379`; untuk penggunaan lokal tanpa Docker, pastikan hostname `redis` mengarah ke `127.0.0.1` pada file `hosts` atau sesuaikan konfigurasi host Redis di `main.py`).

2. Buat dan aktifkan virtual environment Python:
   ```bash
   python -m venv venv
   # Windows (PowerShell)
   .\venv\Scripts\Activate.ps1
   # Linux / macOS
   source venv/bin/activate
   ```

3. Instal seluruh dependensi:
   ```bash
   pip install -r requirements.txt
   ```

4. Jalankan skrip inisialisasi database untuk membuat tabel dan pengguna admin awal:
   ```bash
   python init_db.py
   ```

5. Jalankan server pengembangan menggunakan Uvicorn:
   ```bash
   uvicorn main:app --host 0.0.0.0 --port 8000 --reload
   ```

6. Buka `http://localhost:8000` di peramban.
   * **Username bawaan**: `admin`
   * **Password bawaan**: `admin`
   *(Segera ubah kata sandi bawaan melalui menu Manajemen User setelah berhasil masuk).*

---

## Konfigurasi Produksi

Pada lingkungan produksi (seperti yang dikonfigurasi di dalam `Dockerfile`), aplikasi dijalankan menggunakan **Gunicorn** sebagai manajer proses dengan **8 worker Uvicorn** untuk menangani konkurensi tinggi saat ratusan perangkat peserta melakukan validasi token, koneksi WebSocket, dan pengiriman heartbeat secara bersamaan:

```bash
gunicorn -w 8 -k uvicorn.workers.UvicornWorker main:app --bind 0.0.0.0:8000
```

Disarankan untuk menempatkan reverse proxy seperti **Nginx** di depan kontainer aplikasi untuk menangani terminasi SSL/TLS (HTTPS/WSS) sebelum digunakan pada jaringan ujian skala besar.

