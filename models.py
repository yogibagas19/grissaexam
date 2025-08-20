from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import sessionmaker, declarative_base
from typing import ClassVar

DATABASE_URL = "sqlite:///./database.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    password: ClassVar[str] = None

class AppState(Base):
    __tablename__ = "app_state"
    
    # Hanya akan ada satu baris di tabel ini, jadi ID 1 adalah kuncinya
    id = Column(Integer, primary_key=True, default=1)
    current_token = Column(String, nullable=True)