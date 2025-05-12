# signin.py
"""
Contains functions to render authentication-related UI pages for the Detta application.
"""
import streamlit as st
from streamlit.components.v1 import html
import os
from datetime import datetime, timedelta, timezone
import uuid

from auth import (
    register_user_with_password,
    authenticate_user_with_password,
    get_google_oauth_flow,
    process_google_login,
    create_jwt_token,
    JWT_EXPIRATION_MINUTES,
    initiate_password_reset,
    verify_and_reset_password,
    get_password_strength,
    generate_csrf_token,
    verify_csrf_token
)
from database import get_db, create_session, User, get_password_reset_token

# Google OAuth credentials
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")

# --- Helper for Page Navigation ---
def get_query_params():
    """Gets query parameters from Streamlit's URL."""
    return st.query_params.to_dict()

def set_page(page_name: str, params: dict = None):
    """Navigates to a different page, potentially with query parameters."""
    st.query_params.clear()
    if params:
        st.query_params.from_dict(params)
    st.session_state.current_page = page_name
    st.rerun()

# --- Authentication UI Components ---
def render_login_page():
    """Renders the login page."""
    st.header("Log In to Detta")
    st.markdown(
        """
        <style>
            .form-container {
                background: var(--card-bg);
                padding: 20px;
                border-radius: 12px;
                box-shadow: var(--shadow);
                animation: slideIn 0.5s ease;
            }
            .stForm {
                background: transparent;
            }
            .stForm button {
                width: 100%;
                background: var(--primary);
                color: white;
                border-radius: 8px;
                padding: 12px;
                font-size: 16px;
            }
            .google-btn {
                display: flex; align-items: center; justify-content: center;
                background: #4285F4; color: white !important;
                padding: 12px; border-radius: 8px; text-decoration: none;
                width: 100%; margin-bottom: 15px;
                transition: background 0.2s;
            }
            .google-btn:hover { background: #357AE8; }
            .google-btn img { margin-right: 10px; width: 24px; height: 24px; }
            .divider { text-align: center; margin: 15px 0; color: var(--text-light); }
        </style>
        """, unsafe_allow_html=True
    )

    csrf_token_value = generate_csrf_token()
    with st.container():
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            st.markdown('<div class="form-container">', unsafe_allow_html=True)
            google_flow = get_google_oauth_flow()
            if google_flow:
                auth_url, _ = google_flow.authorization_url(prompt='consent')
                st.markdown(
                    f'<a href="{auth_url}" target="_self" class="google-btn"><img src="https://developers.google.com/identity/images/g-logo.png" alt="Google logo"> Sign in with Google</a>',
                    unsafe_allow_html=True
                )
                st.markdown('<p class="divider">OR</p>', unsafe_allow_html=True)
            elif GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET:
                pass
            else:
                st.warning("Google Sign-In is currently unavailable.")

            with st.form("login_form"):
                email = st.text_input("Email", key="login_email", autocomplete="email", placeholder="your@email.com")
                password = st.text_input("Password", type="password", key="login_password", autocomplete="current-password")
                submitted = st.form_submit_button("Log In")

                if submitted:
                    if not verify_csrf_token(csrf_token_value):
                        st.rerun()
                    if not email or not password:
                        st.error("Please enter both email and password.")
                    else:
                        db_gen = get_db()
                        db = next(db_gen)
                        try:
                            user = authenticate_user_with_password(db, email, password)
                            if user:
                                st.session_state.authenticated = True
                                st.session_state.user_id = user.id
                                st.session_state.user_email = user.email
                                st.session_state.user_name = user.name

                                jwt_payload = {"sub": str(user.id), "name": user.name or user.email}
                                temp_jwt_token = create_jwt_token(data=jwt_payload)
                                expires_at = datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRATION_MINUTES)
                                db_session_obj = create_session(db, user_id=user.id, token="pending_jti", expires_at=expires_at)
                                jwt_payload["jti"] = str(db_session_obj.session_id)
                                final_jwt_token = create_jwt_token(data=jwt_payload)
                                db_session_obj.token = final_jwt_token
                                db.commit()

                                st.session_state.jwt_token = final_jwt_token
                                html(f"<script>localStorage.setItem('detta_jwt_token', '{final_jwt_token}');</script>", height=0)
                                st.success("Logged in successfully!")
                                if 'logger' in st.session_state and st.session_state.logger:
                                    st.session_state.logger.info(f"User {user.email} logged in via password.")
                                set_page("Upload")
                            else:
                                st.error("Invalid email or password.")
                                if 'logger' in st.session_state and st.session_state.logger:
                                    st.session_state.logger.warning(f"Failed login attempt for email: {email}")
                        finally:
                            db.close()

            st.markdown("---")
            col_signup, col_forgot = st.columns(2)
            with col_signup:
                if st.button("Sign Up", key="goto_signup", help="Create a new account"):
                    set_page("signup")
            with col_forgot:
                if st.button("Forgot Password?", key="goto_forgot_password", help="Reset your password"):
                    set_page("forgot_password")
            st.markdown('</div>', unsafe_allow_html=True)

def render_signup_page():
    """Renders the signup page."""
    st.header("Sign Up for Detta")
    st.markdown(
        """
        <style>
            .form-container {
                background: var(--card-bg);
                padding: 20px;
                border-radius: 12px;
                box-shadow: var(--shadow);
                animation: slideIn 0.5s ease;
            }
            .stForm {
                background: transparent;
            }
            .stForm button {
                width: 100%;
                background: var(--primary);
                color: white;
                border-radius: 8px;
                padding: 12px;
                font-size: 16px;
            }
            .google-btn {
                display: flex; align-items: center; justify-content: center;
                background: #4285F4; color: white !important;
                padding: 12px; border-radius: 8px; text-decoration: none;
                width: 100%; margin-bottom: 15px;
                transition: background 0.2s;
            }
            .google-btn:hover { background: #357AE8; }
            .google-btn img { margin-right: 10px; width: 24px; height: 24px; }
            .divider { text-align: center; margin: 15px 0; color: var(--text-light); }
            .password-strength { font-size: 0.9em; margin-top: -10px; margin-bottom: 10px; }
            .password-strength.weak { color: #dc3545; }
            .password-strength.medium { color: #ffc107; }
            .password-strength.strong { color: #28a745; }
        </style>
        """, unsafe_allow_html=True
    )

    csrf_token_value = generate_csrf_token()
    with st.container():
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            st.markdown('<div class="form-container">', unsafe_allow_html=True)
            google_flow = get_google_oauth_flow()
            if google_flow:
                auth_url, _ = google_flow.authorization_url(prompt='consent')
                st.markdown(
                    f'<a href="{auth_url}" target="_self" class="google-btn"><img src="https://developers.google.com/identity/images/g-logo.png" alt="Google logo"> Sign up with Google</a>',
                    unsafe_allow_html=True
                )
                st.markdown('<p class="divider">OR</p>', unsafe_allow_html=True)
            elif GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET:
                pass
            else:
                st.warning("Google Sign-Up is currently unavailable.")

            with st.form("signup_form"):
                name = st.text_input("Name (Optional)", key="signup_name", autocomplete="name")
                email = st.text_input("Email", key="signup_email", autocomplete="email", placeholder="your@email.com")
                password = st.text_input("Password", type="password", key="signup_password", autocomplete="new-password", help="Min 8 chars, letter, number, special char.")
                password_confirm = st.text_input("Confirm Password", type="password", key="signup_password_confirm", autocomplete="new-password")

                strength = get_password_strength(password)
                strength_class = strength.lower().split(" ")[0] if strength else ""
                if strength:
                    st.markdown(f'<div class="password-strength {strength_class}">Password strength: {strength}</div>', unsafe_allow_html=True)

                terms_agreed = st.checkbox("I agree to the [Terms of Service](https://example.com/terms) and [Privacy Policy](https://example.com/privacy).", key="signup_terms")
                submitted = st.form_submit_button("Sign Up")

                if submitted:
                    if not verify_csrf_token(csrf_token_value):
                        st.rerun()
                    if not email or not password or not password_confirm:
                        st.error("Please fill in all required fields.")
                    elif password != password_confirm:
                        st.error("Passwords do not match.")
                    elif not terms_agreed:
                        st.error("You must agree to the Terms and Privacy Policy.")
                    else:
                        db_gen = get_db()
                        db = next(db_gen)
                        try:
                            user, error_message = register_user_with_password(db, email, password, name)
                            if user:
                                st.success("Account created successfully! Please log in.")
                                if 'logger' in st.session_state and st.session_state.logger:
                                    st.session_state.logger.info(f"New user registered: {user.email}")
                                set_page("login")
                            else:
                                st.error(error_message)
                                if 'logger' in st.session_state and st.session_state.logger and error_message:
                                    st.session_state.logger.warning(f"Signup failed for {email}: {error_message}")
                        finally:
                            db.close()

            st.markdown("---")
            if st.button("Already have an account? Log In", key="goto_login_from_signup", help="Back to login"):
                set_page("login")
            st.markdown('</div>', unsafe_allow_html=True)

def render_forgot_password_page():
    """Renders the forgot password request page."""
    st.header("Forgot Password")
    st.markdown(
        """
        <style>
            .form-container {
                background: var(--card-bg);
                padding: 20px;
                border-radius: 12px;
                box-shadow: var(--shadow);
                animation: slideIn 0.5s ease;
            }
            .stForm {
                background: transparent;
            }
            .stForm button {
                width: 100%;
                background: var(--primary);
                color: white;
                border-radius: 8px;
                padding: 12px;
                font-size: 16px;
            }
        </style>
        """, unsafe_allow_html=True
    )

    csrf_token_value = generate_csrf_token()
    with st.container():
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            st.markdown('<div class="form-container">', unsafe_allow_html=True)
            with st.form("forgot_password_form"):
                email = st.text_input("Enter your email address", key="forgot_email", autocomplete="email")
                submitted = st.form_submit_button("Send Reset Link")

                if submitted:
                    if not verify_csrf_token(csrf_token_value):
                        st.rerun()
                    if not email:
                        st.error("Please enter your email address.")
                    else:
                        db_gen = get_db()
                        db = next(db_gen)
                        try:
                            app_base_url = os.getenv("APP_BASE_URL", "http://localhost:8501")
                            if "streamlit.app" in app_base_url and not app_base_url.startswith("https://"):
                                app_base_url = f"https://{app_base_url.split('://')[-1]}"
                            success, message = initiate_password_reset(db, email, app_base_url)
                            if success:
                                st.success(message)
                                if 'logger' in st.session_state and st.session_state.logger:
                                    st.session_state.logger.info(f"Password reset initiated for {email}.")
                            else:
                                st.error(message)
                                if 'logger' in st.session_state and st.session_state.logger:
                                    st.session_state.logger.warning(f"Password reset failed for {email}: {message}")
                        finally:
                            db.close()

            st.markdown("---")
            if st.button("Back to Log In", key="back_to_login_from_forgot", help="Return to login"):
                set_page("login")
            st.markdown('</div>', unsafe_allow_html=True)

def render_reset_password_page():
    """Renders the page to enter a new password using a token."""
    st.header("Reset Your Password")
    st.markdown(
        """
        <style>
            .form-container {
                background: var(--card-bg);
                padding: 20px;
                border-radius: 12px;
                box-shadow: var(--shadow);
                animation: slideIn 0.5s ease;
            }
            .stForm {
                background: transparent;
            }
            .stForm button {
                width: 100%;
                background: var(--primary);
                color: white;
                border-radius: 8px;
                padding: 12px;
                font-size: 16px;
            }
        </style>
        """, unsafe_allow_html=True
    )

    csrf_token_value = generate_csrf_token()
    query_params = get_query_params()
    token_from_url = query_params.get("token", [None])[0]

    if not token_from_url:
        st.error("Invalid or missing password reset token in URL. Please use the link from your email.")
        if st.button("Request New Reset Link", key="request_new_from_reset"):
            set_page("forgot_password")
        return

    with st.container():
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            st.markdown('<div class="form-container">', unsafe_allow_html=True)
            with st.form("reset_password_form"):
                new_password = st.text_input("New Password", type="password", key="reset_new_password", autocomplete="new-password")
                confirm_password = st.text_input("Confirm New Password", type="password", key="reset_confirm_password", autocomplete="new-password")
                submitted = st.form_submit_button("Reset Password")

                if submitted:
                    if not verify_csrf_token(csrf_token_value):
                        st.rerun()
                    if not new_password or not confirm_password:
                        st.error("Please enter and confirm your new password.")
                    elif new_password != confirm_password:
                        st.error("Passwords do not match.")
                    else:
                        db_gen = get_db()
                        db = next(db_gen)
                        try:
                            success, message = verify_and_reset_password(db, token_from_url, new_password)
                            if success:
                                st.success(message)
                                st.info("Redirecting to login page...")
                                if 'logger' in st.session_state and st.session_state.logger:
                                    user_email_for_log = "unknown (token based)"
                                    try:
                                        token_uuid = uuid.UUID(token_from_url)
                                        reset_token_obj_for_log = get_password_reset_token(db, token_uuid)
                                        if reset_token_obj_for_log and reset_token_obj_for_log.user:
                                            user_email_for_log = reset_token_obj_for_log.user.email
                                    except ValueError:
                                        pass
                                    st.session_state.logger.info(f"Password successfully reset for user via token (email: {user_email_for_log}).")
                                set_page("login")
                            else:
                                st.error(message)
                                if 'logger' in st.session_state and st.session_state.logger:
                                    st.session_state.logger.warning(f"Password reset attempt failed with token {token_from_url}: {message}")
                        finally:
                            db.close()

            st.markdown("---")
            if st.button("Back to Log In", key="back_to_login_from_reset_form", help="Return to login"):
                set_page("login")
            st.markdown('</div>', unsafe_allow_html=True)

def handle_google_oauth_callback():
    """Handles the redirect from Google OAuth."""
    st.info("Processing Google login...")
    query_params = get_query_params()
    code = query_params.get("code", [None])[0]
    error = query_params.get("error", [None])[0]

    if error:
        st.error(f"Google OAuth Error: {error}. Please try logging in again.")
        if 'logger' in st.session_state and st.session_state.logger:
            st.session_state.logger.error(f"Google OAuth callback error: {error}")
        set_page("login")
        return

    if not code:
        st.warning("Google OAuth callback incomplete. If you were trying to log in, please try again.")
        if 'logger' in st.session_state and st.session_state.logger:
            st.session_state.logger.warning("Google OAuth callback missing authorization code.")
        return

    db_gen = get_db()
    db = next(db_gen)
    try:
        user = process_google_login(code, db)
        if user:
            st.session_state.authenticated = True
            st.session_state.user_id = user.id
            st.session_state.user_email = user.email
            st.session_state.user_name = user.name

            jwt_payload = {"sub": str(user.id), "name": user.name or user.email}
            temp_jwt_token = create_jwt_token(data=jwt_payload)
            expires_at = datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRATION_MINUTES)
            db_session_obj = create_session(db, user_id=user.id, token="pending_jti", expires_at=expires_at)
            jwt_payload["jti"] = str(db_session_obj.session_id)
            final_jwt_token = create_jwt_token(data=jwt_payload)
            db_session_obj.token = final_jwt_token
            db.commit()

            st.session_state.jwt_token = final_jwt_token
            html(f"<script>localStorage.setItem('detta_jwt_token', '{final_jwt_token}');</script>", height=0)
            st.success("Logged in successfully with Google!")
            if 'logger' in st.session_state and st.session_state.logger:
                st.session_state.logger.info(f"User {user.email} logged in via Google.")
            set_page("Upload")
        else:
            st.error("Failed to log in with Google. Please try again or use email/password.")
            if 'logger' in st.session_state and st.session_state.logger:
                st.session_state.logger.error("process_google_login returned None during OAuth callback.")
            set_page("login")
    except Exception as e:
        st.error(f"An unexpected error occurred during Google sign-in: {e}")
        if 'logger' in st.session_state and st.session_state.logger:
            st.session_state.logger.error(f"Unexpected error in handle_google_oauth_callback: {e}", exc_info=True)
        set_page("login")
    finally:
        db.close()
