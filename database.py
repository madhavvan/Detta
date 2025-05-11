# database.py
"""
Handles database connections, ORM models, and CRUD operations for Detta.
"""
import os
from datetime import datetime, timedelta, timezone

import sqlalchemy
from sqlalchemy import create_engine, Column, String, DateTime, ForeignKey, Text, MetaData
from sqlalchemy.orm import sessionmaker, declarative_base, relationship
from sqlalchemy.dialects.postgresql import UUID
import uuid # For UUID generation

from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise ValueError("DATABASE_URL not set in environment variables or .env file")

engine = create_engine(DATABASE_URL, pool_pre_ping=True, pool_recycle=3600)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()
metadata = MetaData()

# --- ORM Models ---
class User(Base):
    """User model for storing user information."""
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String(255), unique=True, nullable=False, index=True)
    name = Column(String(255), nullable=True)
    password_hash = Column(String(255), nullable=True)
    google_id = Column(String(255), unique=True, nullable=True, index=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_login = Column(DateTime(timezone=True), nullable=True)

    sessions = relationship("Session", back_populates="user", cascade="all, delete-orphan")
    password_reset_tokens = relationship("PasswordResetToken", back_populates="user", cascade="all, delete-orphan")
    # Add relationship to user-specific data if needed, e.g., uploaded files, chat history
    # user_data = relationship("UserData", back_populates="user", cascade="all, delete-orphan")


class Session(Base):
    """Session model for storing user sessions (JWTs)."""
    __tablename__ = "sessions"

    session_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    token = Column(Text, nullable=False) # Storing the JWT itself
    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    user = relationship("User", back_populates="sessions")


class PasswordResetToken(Base):
    """PasswordResetToken model for password recovery."""
    __tablename__ = "password_reset_tokens"

    token = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4) # This is the secure token value itself
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    user = relationship("User", back_populates="password_reset_tokens")

# --- Database Initialization ---
def init_db():
    """Initializes the database by creating tables."""
    try:
        Base.metadata.create_all(bind=engine)
        print("Database tables created successfully (if they didn't exist).")
    except Exception as e:
        print(f"Error creating database tables: {e}")
        # Consider more robust error handling or logging here

def get_db():
    """Dependency to get a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- CRUD Operations ---

# User Operations
def create_user(db: SessionLocal, email: str, name: str = None, password_hash: str = None, google_id: str = None) -> User:
    """Creates a new user in the database."""
    db_user = User(email=email, name=name, password_hash=password_hash, google_id=google_id)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def get_user_by_email(db: SessionLocal, email: str) -> User | None:
    """Retrieves a user by their email address."""
    return db.query(User).filter(User.email == email).first()

def get_user_by_id(db: SessionLocal, user_id: uuid.UUID) -> User | None:
    """Retrieves a user by their ID."""
    return db.query(User).filter(User.id == user_id).first()

def get_user_by_google_id(db: SessionLocal, google_id: str) -> User | None:
    """Retrieves a user by their Google ID."""
    return db.query(User).filter(User.google_id == google_id).first()

def update_user_last_login(db: SessionLocal, user_id: uuid.UUID):
    """Updates the last_login timestamp for a user."""
    db_user = get_user_by_id(db, user_id)
    if db_user:
        db_user.last_login = datetime.now(timezone.utc)
        db.commit()

def update_user_password(db: SessionLocal, user_id: uuid.UUID, new_password_hash: str):
    """Updates the user's password."""
    db_user = get_user_by_id(db, user_id)
    if db_user:
        db_user.password_hash = new_password_hash
        db.commit()

# Session Operations
def create_session(db: SessionLocal, user_id: uuid.UUID, token: str, expires_at: datetime) -> Session:
    """Creates a new session for a user."""
    db_session = Session(user_id=user_id, token=token, expires_at=expires_at)
    db.add(db_session)
    db.commit()
    db.refresh(db_session)
    return db_session

def get_session_by_token(db: SessionLocal, token: str) -> Session | None:
    """Retrieves a session by its token."""
    return db.query(Session).filter(Session.token == token).first()

def delete_session(db: SessionLocal, token: str):
    """Deletes a session by its token."""
    db_session = get_session_by_token(db, token)
    if db_session:
        db.delete(db_session)
        db.commit()

def delete_expired_sessions(db: SessionLocal):
    """Deletes all expired sessions from the database."""
    now = datetime.now(timezone.utc)
    expired_sessions = db.query(Session).filter(Session.expires_at <= now).all()
    for session in expired_sessions:
        db.delete(session)
    if expired_sessions:
        db.commit()
    return len(expired_sessions)

# Password Reset Token Operations
def create_password_reset_token(db: SessionLocal, user_id: uuid.UUID, token_value: uuid.UUID, expires_at: datetime) -> PasswordResetToken:
    """Creates a password reset token."""
    db_token = PasswordResetToken(user_id=user_id, token=token_value, expires_at=expires_at)
    db.add(db_token)
    db.commit()
    db.refresh(db_token)
    return db_token

def get_password_reset_token(db: SessionLocal, token_value: uuid.UUID) -> PasswordResetToken | None:
    """Retrieves a password reset token by its value."""
    return db.query(PasswordResetToken).filter(PasswordResetToken.token == token_value).first()

def delete_password_reset_token(db: SessionLocal, token_value: uuid.UUID):
    """Deletes a password reset token."""
    db_token = get_password_reset_token(db, token_value)
    if db_token:
        db.delete(db_token)
        db.commit()

def delete_expired_password_reset_tokens(db: SessionLocal):
    """Deletes all expired password reset tokens."""
    now = datetime.now(timezone.utc)
    expired_tokens = db.query(PasswordResetToken).filter(PasswordResetToken.expires_at <= now).all()
    for token in expired_tokens:
        db.delete(token)
    if expired_tokens:
        db.commit()
    return len(expired_tokens)

if __name__ == "__main__":
    # This can be used to initialize the database from the command line
    # Ensure your DATABASE_URL is correctly set in your .env file or environment
    print("Initializing database...")
    init_db()
    print("Database initialization complete.")

    # Example: Clean up expired tokens and sessions (can be run periodically)
    # with next(get_db()) as db:
    #     expired_s = delete_expired_sessions(db)
    #     print(f"Deleted {expired_s} expired sessions.")
    #     expired_prt = delete_expired_password_reset_tokens(db)
    #     print(f"Deleted {expired_prt} expired password reset tokens.")