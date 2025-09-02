from passlib.context import CryptContext
from models import Base, engine, SessionLocal, User

pwd_context = CryptContext(schemes=["sha512_crypt"], deprecated="auto")

print("Membuat tabel database...")
Base.metadata.create_all(bind=engine)
print("Tabel berhasil dibuat.")

db = SessionLocal()

admin_username = "admin"
admin_password = "Grissa_2000" # Ganti dengan password yang lebih kuat
hashed_password = pwd_context.hash(admin_password)

existing_user = db.query(User).filter(User.username == admin_username).first()

if not existing_user:
    new_user = User(username=admin_username, hashed_password=hashed_password)
    db.add(new_user)
    db.commit()
    print(f"User '{admin_username}' berhasil dibuat.")
else:
    print(f"User '{admin_username}' sudah ada.")

db.close()