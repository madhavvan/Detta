# auth.py
"""
Handles authentication logic including password hashing, JWT management,
Google OAuth 2.0 flow, and email sending for password reset.
"""
import os
import re
import uuid
import smtplib
import ssl
from email.mime.text import MIMEText
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
from jose import JWTError
import streamlit as st
from google_auth_oauthlib.flow import Flow
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

from dotenv import load_dotenv
from database import (
    get_db,
    User,
    create_user,
    get_user_by_email,
    get_user_by_google_id,
    update_user_last_login,
    create_session,
    get_session_by_token,
    delete_session,
    create_password_reset_token,
    get_password_reset_token,
    delete_password_reset_token,
    update_user_password
)

load_dotenv()

# --- Configuration ---
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_EXPIRATION_MINUTES = int(os.getenv("JWT_EXPIRATION_MINUTES", 1440)) # Default 24 hours

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI") # e.g., "http://localhost:8501/auth/google/callback" or your Streamlit Cloud URL

SMTP_SERVER = os.getenv("SMTP_SERVER")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_USERNAME = os.getenv("SMTP_USERNAME")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
SENDER_EMAIL = os.getenv("SENDER_EMAIL")

if not all([JWT_SECRET_KEY, GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI]):
    st.error("Critical OAuth or JWT configuration is missing. Please check your .env file.")
    # You might want to raise an exception here or handle it more gracefully
    # depending on whether this is a hard stop or a recoverable issue for parts of the app.


# --- Password Utilities ---
def hash_password(password: str) -> str:
    """Hashes a password using bcrypt."""
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password.decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plain password against a hashed password."""
    if not hashed_password: # Handles cases where password_hash might be None (e.g. Google SSO user)
        return False
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

def is_strong_password(password: str) -> bool:
    """
    Checks if a password meets strength requirements:
    - Minimum 8 characters
    - At least one letter
    - At least one number
    - At least one special character
    """
    if len(password) < 8:
        return False
    if not re.search(r"[a-zA-Z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]", password): # OWASP recommended special chars
        return False
    return True

def get_password_strength(password: str) -> str:
    """Provides a textual feedback on password strength."""
    if not password:
        return ""
    if len(password) < 8:
        return "Weak (too short)"
    score = 0
    if re.search(r"[a-z]", password): score +=1
    if re.search(r"[A-Z]", password): score +=1
    if re.search(r"[0-9]", password): score +=1
    if re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]", password): score +=1

    if score == 4 and len(password) >= 12: return "Strong"
    if score >= 3 and len(password) >= 8: return "Medium"
    return "Weak"


# --- JWT Utilities ---
def create_jwt_token(data: dict, expires_delta: timedelta = None) -> str:
    """Creates a JWT token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRATION_MINUTES)
    to_encode.update({"exp": expire, "iat": datetime.now(timezone.utc)})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return encoded_jwt

def verify_jwt_token(token: str, db: next(get_db())) -> User | None:
    """
    Verifies a JWT token.
    Returns the user object if the token is valid and corresponds to an active session,
    otherwise None.
    """
    if not token:
        return None
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        user_id_str: str = payload.get("sub") # Assuming 'sub' contains the user_id
        session_token_db: str = payload.get("jti") # Assuming 'jti' contains the session_id/token from db

        if user_id_str is None or session_token_db is None:
            return None # Token is malformed

        user_id = uuid.UUID(user_id_str)

        # Check if the session exists in the database and matches the token
        session = get_session_by_token(db, session_token_db)
        if not session or session.user_id != user_id or session.expires_at <= datetime.now(timezone.utc):
            if session: # Session expired or mismatched
                delete_session(db, session.token)
            return None

        user = db.query(User).filter(User.id == user_id).first()
        return user
    except JWTError: # Covers ExpiredSignatureError, InvalidTokenError, etc.
        # Attempt to delete if we can parse the jti, otherwise it's an invalid token
        try:
            unverified_payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM], options={"verify_signature": False, "verify_exp": False})
            session_token_to_delete = unverified_payload.get("jti")
            if session_token_to_delete:
                delete_session(db, session_token_to_delete)
        except JWTError:
            pass # Could not decode to get jti
        return None
    except Exception: # Catch other potential errors like UUID conversion
        return None


# --- Google OAuth 2.0 Utilities ---
def get_google_oauth_flow():
    """Initializes and returns the Google OAuth flow."""
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET or not GOOGLE_REDIRECT_URI:
        st.error("Google OAuth credentials are not configured.")
        return None
    try:
        client_config = {
            "web": {
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
                "redirect_uris": [GOOGLE_REDIRECT_URI]
            }
        }
        flow = Flow.from_client_config(
            client_config=client_config,
            scopes=['openid', 'https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile']
        )
        flow.redirect_uri = GOOGLE_REDIRECT_URI
        return flow
    except Exception as e:
        st.error(f"Error initializing Google OAuth flow: {e}")
        print(f"Error initializing Google OAuth flow: {e}")
        return None

def process_google_login(code: str, db: next(get_db())) -> User | None:
    """
    Processes the Google login after the user is redirected back from Google.
    Exchanges the authorization code for tokens, retrieves user info,
    and creates/updates the user in the database.
    Returns the user object on successful login.
    """
    flow = get_google_oauth_flow()
    if not flow:
        return None

    try:
        flow.fetch_token(code=code)
        credentials = flow.credentials
        id_info = id_token.verify_oauth2_token(
            credentials.id_token, google_requests.Request(session=flow.authorized_session()), GOOGLE_CLIENT_ID
        )

        google_id = id_info.get('sub')
        email = id_info.get('email')
        name = id_info.get('name')

        if not email:
            st.error("Could not retrieve email from Google profile.")
            return None

        user = get_user_by_google_id(db, google_id)
        if not user:
            user = get_user_by_email(db, email) # Check if user exists with this email (e.g. signed up with password)
            if user:
                # Link Google ID to existing account
                user.google_id = google_id
            else:
                # Create new user
                user = create_user(db, email=email, name=name, google_id=google_id)
        else:
            # Update name if it changed, though typically Google ID is fixed
            if user.name != name:
                user.name = name

        update_user_last_login(db, user.id)
        db.commit()
        db.refresh(user)
        return user

    except Exception as e:
        st.error(f"Error processing Google login: {e}")
        # Log this error for debugging
        print(f"Google login error: {e}")
        return None


# --- Email Sending Utility (for Password Reset) ---
def send_password_reset_email(recipient_email: str, reset_link: str):
    """Sends a password reset email to the user."""
    if not all([SMTP_SERVER, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD, SENDER_EMAIL]):
        st.error("Email server (SMTP) is not configured. Password reset email cannot be sent.")
        print("SMTP configuration missing. Cannot send password reset email.")
        return False

    message = MIMEText(f"""
    Hello,

    You requested a password reset for your Detta account.
    Please click the link below to reset your password. This link is valid for 1 hour.

    {reset_link}

    If you did not request this, please ignore this email.

    Thanks,
    The Detta Team
    """)
    message["Subject"] = "Detta - Password Reset Request"
    message["From"] = SENDER_EMAIL
    message["To"] = recipient_email

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls(context=context) # Secure the connection
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.sendmail(SENDER_EMAIL, recipient_email, message.as_string())
        print(f"Password reset email sent to {recipient_email}")
        return True
    except Exception as e:
        st.error(f"Failed to send password reset email: {e}")
        print(f"SMTP Error: {e}")
        return False


# --- Core Authentication Functions ---
def register_user_with_password(db: next(get_db()), email: str, password: str, name: str = None) -> tuple[User | None, str | None]:
    """Registers a new user with email and password."""
    if get_user_by_email(db, email):
        return None, "Email already registered."
    if not is_strong_password(password):
        return None, "Password is not strong enough. Min 8 chars, letter, number, special char."

    hashed = hash_password(password)
    try:
        user = create_user(db, email=email, name=name, password_hash=hashed)
        return user, None
    except Exception as e:
        # Log the exception e
        print(f"Error during user registration: {e}")
        return None, "An error occurred during registration. Please try again."


def authenticate_user_with_password(db: next(get_db()), email: str, password: str) -> User | None:
    """Authenticates a user with email and password."""
    user = get_user_by_email(db, email)
    if not user or not user.password_hash: # No user or user signed up with Google only
        return None
    if not verify_password(password, user.password_hash):
        return None
    update_user_last_login(db, user.id)
    db.commit() # Ensure last_login is saved
    return user


def initiate_password_reset(db: next(get_db()), email: str, app_base_url: str) -> tuple[bool, str]:
    """
    Initiates the password reset process.
    Generates a token, stores it, and sends an email with the reset link.
    `app_base_url` should be like 'http://localhost:8501' or 'https://your-app.streamlit.app'
    """
    user = get_user_by_email(db, email)
    if not user:
        return False, "No user found with that email address."
    if not user.password_hash: # User likely signed up via Google
        return False, "This account was created using Google Sign-In. Please use Google to log in or manage your password via Google."


    # Invalidate any existing tokens for this user
    existing_tokens = db.query(PasswordResetToken).filter(PasswordResetToken.user_id == user.id).all()
    for t in existing_tokens:
        db.delete(t)
    db.commit()

    token_value = uuid.uuid4()
    expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
    create_password_reset_token(db, user_id=user.id, token_value=token_value, expires_at=expires_at)

    # Construct reset link (ensure your app handles /reset-password?token=<token_value> route)
    reset_link = f"{app_base_url}/?page=reset_password&token={token_value}"

    if send_password_reset_email(user.email, reset_link):
        return True, "Password reset link sent to your email. Please check your inbox (and spam folder)."
    else:
        # Clean up token if email failed to prevent unusable tokens
        delete_password_reset_token(db, token_value)
        return False, "Failed to send password reset email. Please try again later or contact support."

def verify_and_reset_password(db: next(get_db()), token_value_str: str, new_password: str) -> tuple[bool, str]:
    """Verifies the reset token and updates the user's password."""
    try:
        token_value = uuid.UUID(token_value_str)
    except ValueError:
        return False, "Invalid token format."

    reset_token_obj = get_password_reset_token(db, token_value)

    if not reset_token_obj:
        return False, "Invalid or expired password reset token."
    if reset_token_obj.expires_at <= datetime.now(timezone.utc):
        delete_password_reset_token(db, token_value) # Clean up expired token
        return False, "Password reset token has expired. Please request a new one."

    if not is_strong_password(new_password):
        return False, "New password is not strong enough. Min 8 chars, letter, number, special char."

    user = get_user_by_id(db, reset_token_obj.user_id)
    if not user:
        delete_password_reset_token(db, token_value) # Clean up
        return False, "User associated with this token no longer exists." # Should not happen

    new_password_hash = hash_password(new_password)
    update_user_password(db, user.id, new_password_hash)
    delete_password_reset_token(db, token_value) # Invalidate token after use
    return True, "Password has been successfully reset. You can now log in with your new password."


# --- CSRF Protection ---
def generate_csrf_token():
    """Generates a CSRF token and stores it in session state."""
    if 'csrf_token' not in st.session_state or not st.session_state.csrf_token:
        st.session_state.csrf_token = str(uuid.uuid4())
    return st.session_state.csrf_token

def verify_csrf_token(form_csrf_token: str):
    """Verifies the CSRF token from a form against the one in session state."""
    session_csrf_token = st.session_state.get('csrf_token')
    if not session_csrf_token or session_csrf_token != form_csrf_token:
        st.error("CSRF token mismatch. Please try submitting the form again.")
        return False
    # Invalidate token after use for single-use, or regenerate for next form
    # For simplicity in Streamlit's rerun model, we might regenerate it on each page load.
    # Or, if one form per page, could clear it here: del st.session_state.csrf_token
    return True