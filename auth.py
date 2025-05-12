# corrected_auth.py
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
import logging # Standard Python logging

import bcrypt
import jwt
from jose import JWTError # Python-jose's JWTError
import streamlit as st
from google_auth_oauthlib.flow import Flow
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

from dotenv import load_dotenv
from database import (
    get_db,
    User,
    PasswordResetToken, # Import for type hinting or direct use if needed
    create_user,
    get_user_by_email,
    get_user_by_id, # Added import
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

# Initialize a logger for this module if st.session_state.logger is not available/appropriate
module_logger = logging.getLogger(__name__)
if not module_logger.handlers:
    # Configure module_logger if necessary, or rely on app_logger if passed/accessible
    # For now, assume app_logger from Streamlit context will be used when possible
    pass


# --- Configuration ---
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_EXPIRATION_MINUTES = int(os.getenv("JWT_EXPIRATION_MINUTES", 1440)) # Default 24 hours

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
# Ensure GOOGLE_REDIRECT_URI includes the page for callback handling
# e.g., "http://localhost:8501/?page=google_oauth_callback" or
# "https://your-app.streamlit.app/?page=google_oauth_callback"
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI")


SMTP_SERVER = os.getenv("SMTP_SERVER")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_USERNAME = os.getenv("SMTP_USERNAME")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
SENDER_EMAIL = os.getenv("SENDER_EMAIL")

if not all([JWT_SECRET_KEY]): # GOOGLE specifics checked where Google Auth is used
    # Log this as an error, potentially to a dedicated auth log if needed
    module_logger.critical("JWT_SECRET_KEY is missing. Authentication will fail.")
    # Raising an error might be too disruptive if only parts of auth are affected
    # st.error("Critical JWT configuration is missing.") # Avoid st calls in non-UI part


# --- Password Utilities ---
def hash_password(password: str) -> str:
    """Hashes a password using bcrypt."""
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password.decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plain password against a hashed password."""
    if not hashed_password:
        return False
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

def is_strong_password(password: str) -> bool:
    if len(password) < 8:
        return False
    if not re.search(r"[a-zA-Z]", password): # Simplified: at least one letter
        return False
    if not re.search(r"[0-9]", password):
        return False
    # OWASP: "Length is the most important factor. Complexity requirements... increase password overhead... without a measurable benefit."
    # Consider simplifying or focusing on length + breach checks if possible.
    # For now, keeping special char requirement:
    if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]", password):
        return False
    return True

def get_password_strength(password: str) -> str:
    if not password:
        return ""
    score = 0
    length = len(password)

    if length < 8: return "Weak (too short)"
    if length >= 12: score += 1 # Bonus for longer passwords

    if re.search(r"[a-z]", password): score +=1
    if re.search(r"[A-Z]", password): score +=1
    if re.search(r"[0-9]", password): score +=1
    if re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]", password): score +=1

    if score >= 4: return "Strong" # At least 3 char types + bonus/decent length
    if score >= 3: return "Medium"
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
    if not token:
        return None
    app_logger = st.session_state.get("logger", module_logger)
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        user_id_str: str = payload.get("sub")
        session_jti_str: str = payload.get("jti") # JWT ID, should match session_id in DB

        if user_id_str is None or session_jti_str is None:
            app_logger.warning("JWT missing sub or jti.")
            return None

        user_id = uuid.UUID(user_id_str)
        session_jti = uuid.UUID(session_jti_str) # The jti is the session_id

        # Check if the session exists in the database and matches the token's jti
        # Assuming session_id in DB is what 'jti' refers to.
        db_session = db.query(User.Session).filter(User.Session.session_id == session_jti).first()

        if not db_session:
            app_logger.warning(f"No DB session found for jti: {session_jti}")
            return None
        if db_session.user_id != user_id:
            app_logger.warning(f"Session jti {session_jti} user_id mismatch.")
            return None
        if db_session.expires_at <= datetime.now(timezone.utc):
            app_logger.info(f"Session jti {session_jti} expired. Deleting.")
            delete_session(db, db_session.token) # Assuming delete_session takes the full JWT token string
                                                # or change delete_session to take jti
            return None
        if db_session.token != token: # Ensure the stored token matches the presented one
            app_logger.warning(f"Presented token does not match stored token for jti {session_jti}.")
            # This could be a sign of token reuse or an issue with token storage/retrieval logic.
            # For now, we'll treat it as invalid.
            return None


        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            app_logger.warning(f"No user found for id: {user_id} from JWT.")
        return user
    except jwt.ExpiredSignatureError:
        app_logger.info("JWT expired.")
        # Attempt to delete if we can parse the jti, otherwise it's an invalid token
        try:
            unverified_payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM], options={"verify_signature": False, "verify_exp": False})
            session_token_jti_to_delete = unverified_payload.get("jti")
            if session_token_jti_to_delete:
                # This assumes delete_session can handle deletion by jti or you have a specific function
                # delete_session_by_jti(db, uuid.UUID(session_token_jti_to_delete))
                pass # Placeholder: implement session deletion by jti if needed for cleanup
        except jwt.DecodeError:
             app_logger.warning("Could not decode expired JWT to get jti for cleanup.")
        return None
    except (JWTError, jwt.InvalidTokenError, ValueError) as e: # Catches python-jose errors, PyJWT errors, and UUID conversion errors
        app_logger.warning(f"Invalid JWT: {e}")
        return None
    except Exception as e: # Catch other potential errors
        app_logger.error(f"Unexpected error during JWT verification: {e}", exc_info=True)
        return None


# --- Google OAuth 2.0 Utilities ---
def get_google_oauth_flow():
    app_logger = st.session_state.get("logger", module_logger)
    if not all([GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI]):
        msg = "Google OAuth credentials (CLIENT_ID, CLIENT_SECRET, or REDIRECT_URI) are not configured."
        app_logger.error(msg)
        # st.error(msg) # Avoid UI calls here directly
        return None
    try:
        client_config = {
            "web": {
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
                "redirect_uris": [GOOGLE_REDIRECT_URI.split('?')[0]] # Base URI without query params for client config
            }
        }
        flow = Flow.from_client_config(
            client_config=client_config,
            scopes=['openid', 'https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile']
        )
        flow.redirect_uri = GOOGLE_REDIRECT_URI # Full redirect URI for the flow instance
        return flow
    except Exception as e:
        app_logger.error(f"Error initializing Google OAuth flow: {e}", exc_info=True)
        return None

def process_google_login(code: str, db: next(get_db())) -> User | None:
    app_logger = st.session_state.get("logger", module_logger)
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
            app_logger.error("Could not retrieve email from Google profile.")
            # st.error("Could not retrieve email from Google profile.")
            return None

        user = get_user_by_google_id(db, google_id)
        if not user:
            user = get_user_by_email(db, email)
            if user:
                user.google_id = google_id # Link Google ID
                user.name = user.name or name # Update name if not set or Google's is better
            else:
                user = create_user(db, email=email, name=name, google_id=google_id)
        else:
            if user.name != name and name: # Update name if changed
                user.name = name

        update_user_last_login(db, user.id)
        db.commit()
        db.refresh(user)
        app_logger.info(f"Google login processed successfully for user {email}.")
        return user

    except Exception as e:
        app_logger.error(f"Error processing Google login: {e}", exc_info=True)
        # st.error(f"Error processing Google login: {e}")
        return None


# --- Email Sending Utility (for Password Reset) ---
def send_password_reset_email(recipient_email: str, reset_link: str):
    app_logger = st.session_state.get("logger", module_logger)
    if not all([SMTP_SERVER, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD, SENDER_EMAIL]):
        msg = "Email server (SMTP) is not configured. Password reset email cannot be sent."
        app_logger.error(msg)
        # st.error(msg)
        return False

    message_body = f"""
    Hello,

    You requested a password reset for your Detta account.
    Please click the link below to reset your password. This link is valid for 1 hour.

    {reset_link}

    If you did not request this, please ignore this email.

    Thanks,
    The Detta Team
    """
    message = MIMEText(message_body)
    message["Subject"] = "Detta - Password Reset Request"
    message["From"] = SENDER_EMAIL
    message["To"] = recipient_email

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls(context=context)
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.sendmail(SENDER_EMAIL, recipient_email, message.as_string())
        app_logger.info(f"Password reset email sent to {recipient_email}")
        return True
    except Exception as e:
        app_logger.error(f"Failed to send password reset email to {recipient_email}: {e}", exc_info=True)
        # st.error(f"Failed to send password reset email: {e}")
        return False


# --- Core Authentication Functions ---
def register_user_with_password(db: next(get_db()), email: str, password: str, name: str = None) -> tuple[User | None, str | None]:
    app_logger = st.session_state.get("logger", module_logger)
    if get_user_by_email(db, email):
        return None, "Email already registered."
    strength_feedback = get_password_strength(password)
    if not is_strong_password(password): # Use the direct check
        return None, f"Password is not strong enough. ({strength_feedback}). Min 8 chars, letter, number, special char."

    hashed = hash_password(password)
    try:
        user = create_user(db, email=email, name=name, password_hash=hashed)
        app_logger.info(f"User {email} registered successfully with password.")
        return user, None
    except Exception as e:
        app_logger.error(f"Error during user registration for {email}: {e}", exc_info=True)
        return None, "An error occurred during registration. Please try again."


def authenticate_user_with_password(db: next(get_db()), email: str, password: str) -> User | None:
    app_logger = st.session_state.get("logger", module_logger)
    user = get_user_by_email(db, email)
    if not user or not user.password_hash:
        app_logger.warning(f"Authentication attempt for non-existent or passwordless user: {email}")
        return None
    if not verify_password(password, user.password_hash):
        app_logger.warning(f"Invalid password attempt for user: {email}")
        return None
    update_user_last_login(db, user.id)
    db.commit()
    app_logger.info(f"User {email} authenticated successfully with password.")
    return user


def initiate_password_reset(db: next(get_db()), email: str, app_base_url: str) -> tuple[bool, str]:
    app_logger = st.session_state.get("logger", module_logger)
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
    app_logger.info(f"Invalidated existing password reset tokens for user {email}.")

    token_value = uuid.uuid4() # This is the actual token string
    expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
    create_password_reset_token(db, user_id=user.id, token_value=token_value, expires_at=expires_at)

    reset_link = f"{app_base_url}?page=reset_password&token={token_value}"

    if send_password_reset_email(user.email, reset_link):
        app_logger.info(f"Password reset link successfully sent to {email}.")
        return True, "Password reset link sent to your email. Please check your inbox (and spam folder)."
    else:
        delete_password_reset_token(db, token_value) # Clean up token if email failed
        app_logger.warning(f"Failed to send password reset email to {email}, token cleaned up.")
        return False, "Failed to send password reset email. Please try again later or contact support."

def verify_and_reset_password(db: next(get_db()), token_value_str: str, new_password: str) -> tuple[User | None, str]:
    """Verifies the reset token, updates password. Returns (User object or None, message)."""
    app_logger = st.session_state.get("logger", module_logger)
    try:
        token_value = uuid.UUID(token_value_str)
    except ValueError:
        return None, "Invalid token format."

    reset_token_obj = get_password_reset_token(db, token_value)

    if not reset_token_obj:
        return None, "Invalid or expired password reset token."
    if reset_token_obj.expires_at <= datetime.now(timezone.utc):
        delete_password_reset_token(db, token_value) # Clean up expired token
        app_logger.warning(f"Expired password reset token used: {token_value_str}")
        return None, "Password reset token has expired. Please request a new one."

    if not is_strong_password(new_password):
        return None, "New password is not strong enough. Min 8 chars, letter, number, special char."

    user = get_user_by_id(db, reset_token_obj.user_id) # Re-fetch user
    if not user:
        delete_password_reset_token(db, token_value) # Clean up
        app_logger.error(f"User not found for valid password reset token: {token_value_str}, user_id: {reset_token_obj.user_id}")
        return None, "User associated with this token no longer exists."

    new_password_hash = hash_password(new_password)
    update_user_password(db, user.id, new_password_hash)
    delete_password_reset_token(db, token_value) # Invalidate token after use
    app_logger.info(f"Password successfully reset for user {user.email} via token.")
    return user, "Password has been successfully reset. You can now log in with your new password."


# --- CSRF Protection ---
def generate_csrf_token():
    """Generates a CSRF token and stores it in session state."""
    if 'csrf_token' not in st.session_state or not st.session_state.csrf_token:
        st.session_state.csrf_token = str(uuid.uuid4())
    return st.session_state.csrf_token

def verify_csrf_token(form_csrf_token: str):
    """
    Verifies the CSRF token from a form against the one in session state.
    Invalidates the token after successful verification for single-use.
    """
    app_logger = st.session_state.get("logger", module_logger)
    session_csrf_token = st.session_state.get('csrf_token')
    if not session_csrf_token or session_csrf_token != form_csrf_token:
        app_logger.warning("CSRF token mismatch.")
        st.error("CSRF token mismatch. Please try submitting the form again.")
        return False
    # Invalidate token after successful use to make it single-use
    del st.session_state.csrf_token
    app_logger.info("CSRF token verified successfully and invalidated.")
    return True
