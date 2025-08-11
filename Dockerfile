# Gunakan base image Python yang ringan
FROM python:3.11-slim

# Tetapkan direktori kerja di dalam kontainer
WORKDIR /app

# Salin file daftar pustaka terlebih dahulu untuk efisiensi cache
COPY requirements.txt .

# Instal semua pustaka yang dibutuhkan
RUN pip install --no-cache-dir -r requirements.txt

# Salin semua sisa file proyek ke dalam direktori kerja
COPY . .

# Perintah untuk menjalankan aplikasi saat kontainer dimulai
# Penting: Gunakan --host 0.0.0.0 agar bisa diakses dari luar kontainer
CMD ["gunicorn", "-w", "2", "-k", "uvicorn.workers.UvicornWorker", "main:app", "--bind", "0.0.0.0:8000"]