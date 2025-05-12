# app.py
"""
Main application file for Detta.
Handles page routing, authentication, and session management with a modern UI.
"""
import streamlit as st
from streamlit.runtime.scriptrunner import get_script_run_ctx
from streamlit.components.v1 import html
import logging
from logging.handlers import RotatingFileHandler
import os
from datetime import datetime, timedelta, timezone
import uuid
from collections import deque
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# --- Module Imports ---
from signin import (
    render_login_page,
    render_signup_page,
    render_forgot_password_page,
    render_reset_password_page,
    handle_google_oauth_callback,
    get_query_params,
    set_page
)
from ui import (
    render_upload_page,
    render_clean_page,
    render_insights_page,
    render_visualization_page
)
from auth import verify_jwt_token, create_jwt_token, JWT_EXPIRATION_MINUTES, delete_session
from database import get_db, User, Session as DbSession, init_db as initialize_database, delete_expired_sessions
from data_utils import initialize_openai_client, chat_with_gpt, get_auto_suggestions

# --- Configuration ---
st.set_page_config(page_title="Detta", layout="wide", initial_sidebar_state="expanded")

# --- Custom CSS and JavaScript ---
st.markdown("""
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;700&display=swap');

        :root {
            --primary: #1E88E5;
            --secondary: #43A047;
            --background: #F5F7FA;
            --card-bg: #FFFFFF;
            --text: #333333;
            --text-light: #B0BEC5;
            --shadow: 0 4px 12px rgba(0,0,0,0.1);
        }

        [data-theme="dark"] {
            --background: #1A1A1A;
            --card-bg: #2A2A2A;
            --text: #E0E0E0;
            --text-light: #78909C;
        }

        body {
            font-family: 'Inter', sans-serif;
            background-color: var(--background);
            color: var(--text);
            transition: all 0.3s ease;
        }

        .main {
            padding: 20px;
            border-radius: 12px;
            min-height: 100vh;
        }

        h1, h2, h3 {
            font-weight: 700;
            color: var(--text);
        }

        h1 { font-size: 32px; margin-bottom: 20px; }
        h2 { font-size: 24px; }
        h3 { font-size: 18px; }

        .stButton>button {
            background-color: var(--primary);
            color: white;
            border-radius: 8px;
            font-size: 16px;
            padding: 12px 24px;
            border: none;
            transition: transform 0.2s, box-shadow 0.2s;
        }

        .stButton>button:hover {
            transform: translateY(-2px);
            box-shadow: var(--shadow);
        }

        .stTextInput input, .stTextArea textarea {
            border: 1px solid #B0BEC5;
            border-radius: 8px;
            padding: 12px;
            background-color: var(--card-bg);
            color: var(--text);
        }

        .sidebar .sidebar-content {
            background-color: var(--card-bg);
            border-radius: 12px;
            padding: 20px;
            box-shadow: var(--shadow);
        }

        .sidebar .stRadio>label {
            font-size: 16px;
            color: var(--text);
            padding: 10px;
            border-radius: 8px;
            transition: background-color 0.2s;
        }

        .sidebar .stRadio>label:hover {
            background-color: rgba(30, 136, 229, 0.1);
        }

        .stDataFrame {
            border: 1px solid #B0BEC5;
            border-radius: 8px;
            padding: 10px;
            background-color: var(--card-bg);
        }

        .chat-container {
            max-height: 300px;
            overflow-y: auto;
            margin-bottom: 20px;
            border-radius: 8px;
            background-color: var(--card-bg);
            padding: 10px;
        }

        .chat-bubble-user {
            background-color: var(--primary);
            color: white;
            padding: 12px;
            border-radius: 12px 12px 0 12px;
            margin: 10px 0;
            max-width: 70%;
            float: right;
            clear: both;
            animation: fadeIn 0.5s ease;
        }

        .chat-bubble-assistant {
            background-color: #E0E0E0;
            color: #333;
            padding: 12px;
            border-radius: 12px 12px 12px 0;
            margin: 10px 0;
            max-width: 70%;
            float: left;
            clear: both;
            animation: fadeIn 0.5s ease;
        }

        .auth-container {
            max-width: 500px;
            margin: 2rem auto;
            padding: 2rem;
            background-color: var(--card-bg);
            border-radius: 12px;
            box-shadow: var(--shadow);
            animation: slideIn 0.5s ease;
        }

        .theme-toggle {
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 1000;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }

        @keyframes slideIn {
            from { opacity: 0; transform: translateY(-20px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .stSpinner > div {
            border-color: var(--primary) transparent var(--primary) transparent !important;
        }
    </style>
    <script>
        // Theme toggle and persistence
        function toggleTheme() {
            const currentTheme = document.documentElement.getAttribute('data-theme');
            const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
            document.documentElement.setAttribute('data-theme', newTheme);
            localStorage.setItem('detta_theme', newTheme);
        }

        // Load theme from localStorage
        document.addEventListener('DOMContentLoaded', () => {
            const savedTheme = localStorage.getItem('detta_theme') || 'light';
            document.documentElement.setAttribute('data-theme', savedTheme);

            // JWT token persistence
            const token = localStorage.getItem('detta_jwt_token');
            if (token && !window.location.search.includes('jwt_token')) {
                window.location.href = window.location.pathname + '?jwt_token=' + encodeURIComponent(token);
            }
        });
    </script>
""", unsafe_allow_html=True)

# --- Theme Toggle Button ---
def render_theme_toggle():
    html("""
        <div class="theme-toggle">
            <button onclick="toggleTheme()" style="background: var(--primary); color: white; border: none; border-radius: 50%; width: 40px; height: 40px; cursor: pointer;">
                🌙
            </button>
        </div>
    """, height=50)

# --- Logging Setup ---
def setup_logger():
    if 'logger_initialized' in st.session_state:
        return st.session_state.logger

    user_identifier = "anonymous"
    if st.session_state.get("authenticated") and st.session_state.get("user_email"):
        user_identifier = st.session_state.user_email.split('@')[0]
    elif hasattr(st.runtime, 'scriptrunner') and hasattr(st.runtime.scriptrunner, 'get_script_run_ctx'):
        ctx = st.runtime.scriptrunner.get_script_run_ctx()
        if ctx:
            user_identifier = f"session_{ctx.session_id[:8]}"
    else:
        user_identifier = f"session_{uuid.uuid4().hex[:8]}"

    log_dir = "/tmp/detta_logs"
    if not os.path.exists(log_dir):
        try:
            os.makedirs(log_dir)
        except OSError as e:
            print(f"Warning: Could not create log directory {log_dir}: {e}. Logging to current dir.")
            log_dir = "."

    log_file_name = f"detta_log_{user_identifier}_{datetime.now().strftime('%Y%m%d')}.log"
    log_file_path = os.path.join(log_dir, log_file_name)

    logger = logging.getLogger("DettaApp")
    logger.setLevel(logging.INFO)

    if not logger.handlers:
        handler = RotatingFileHandler(log_file_path, maxBytes=10*1024*1024, backupCount=3, encoding='utf-8')
        formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(module)s - %(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    st.session_state.logger = logger
    st.session_state.logger_initialized = True
    logger.info(f"Logger initialized for {user_identifier}. Log file: {log_file_path}")
    return logger

# Initialize logger
app_logger = setup_logger()

# --- Session State Initialization ---
def initialize_session_state():
    defaults = {
        "authenticated": False,
        "user_id": None,
        "user_email": None,
        "user_name": "Guest",
        "jwt_token": None,
        "current_page": "login",
        "last_activity": datetime.now(timezone.utc),
        "df": None,
        "cleaned_df": None,
        "chat_history": [],
        "suggestions": [],
        "vis_suggestions": [],
        "cleaning_history": deque(maxlen=5),
        "pinned_chats": [],
        "logs": [],
        "onboarding_seen": False,
        "api_key_valid": None,
        "current_data_page": 0,
        "is_dask": False,
        "app_logs": [],
        "csrf_token": None
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value

    # Restore authentication from JWT token
    query_params = get_query_params()
    token_from_query = query_params.get("jwt_token", [None])[0]
    if token_from_query and not st.session_state.jwt_token:
        st.session_state.jwt_token = token_from_query
        app_logger.info("Retrieved JWT token from query parameter.")

    if st.session_state.jwt_token and not st.session_state.authenticated:
        db_gen = get_db()
        db = next(db_gen)
        try:
            user = verify_jwt_token(st.session_state.jwt_token, db)
            if user:
                st.session_state.authenticated = True
                st.session_state.user_id = user.id
                st.session_state.user_email = user.email
                st.session_state.user_name = user.name or user.email
                st.session_state.last_activity = datetime.now(timezone.utc)
                st.session_state.current_page = "Upload"
                app_logger.info(f"User {user.email} re-authenticated via session JWT.")
            else:
                st.session_state.jwt_token = None
                html("<script>localStorage.removeItem('detta_jwt_token');</script>", height=0)
                app_logger.info("Invalid or expired session JWT found. Cleared from localStorage.")
        except Exception as e:
            app_logger.error(f"Error validating JWT token: {e}")
            st.session_state.jwt_token = None
            html("<script>localStorage.removeItem('detta_jwt_token');</script>", height=0)
        finally:
            db_gen.close()

initialize_session_state()
render_theme_toggle()

# --- Database Initialization ---
try:
    initialize_database()
    with next(get_db()) as db:
        delete_expired_sessions(db)
except Exception as e:
    app_logger.error(f"Database initialization or cleanup error: {e}")
    st.error(f"A critical database error occurred: {e}. Some features might be unavailable.")

# --- OpenAI Client Initialization ---
if 'openai_client' not in st.session_state:
    st.session_state.openai_client = initialize_openai_client()
    if st.session_state.openai_client:
        st.session_state.api_key_valid = True
        app_logger.info("OpenAI API client initialized successfully.")
    else:
        st.session_state.api_key_valid = False
        app_logger.warning("OpenAI API key missing or invalid. AI features may be disabled.")
openai_client = st.session_state.openai_client

# --- Session Timeout Logic ---
SESSION_TIMEOUT_MINUTES = 30
if st.session_state.authenticated:
    st.session_state.last_activity = datetime.now(timezone.utc)
    time_since_last_activity = datetime.now(timezone.utc) - st.session_state.last_activity
    if time_since_last_activity > timedelta(minutes=SESSION_TIMEOUT_MINUTES):
        app_logger.info(f"User {st.session_state.user_email} session timed out due to inactivity.")
        if st.session_state.jwt_token:
            with next(get_db()) as db:
                delete_session(db, st.session_state.jwt_token)
        st.session_state.authenticated = False
        st.session_state.user_id = None
        st.session_state.user_email = None
        st.session_state.user_name = "Guest"
        st.session_state.jwt_token = None
        html("<script>localStorage.removeItem('detta_jwt_token');</script>", height=0)
        st.session_state.current_page = "login"
        st.warning("Your session has timed out. Please log in again.")
        st.rerun()

# --- Page Routing ---
query_params = get_query_params()
page_param = query_params.get("page", [None])[0]
oauth_callback_code = query_params.get("code", [None])[0]

app_logger.info(f"Query params on page load: {query_params}, page_param: {page_param}")

if page_param and page_param != st.session_state.current_page:
    if page_param in ["login", "signup", "forgot_password", "reset_password", "google_oauth_callback"]:
        st.session_state.current_page = page_param
    elif st.session_state.authenticated and page_param in ["Upload", "Clean", "Insights", "Visualize"]:
        st.session_state.current_page = page_param

if st.session_state.current_page == "google_oauth_callback" or (oauth_callback_code and not st.session_state.authenticated):
    st.session_state.current_page = "google_oauth_callback"
    handle_google_oauth_callback()

# --- Sidebar and Main Content ---
if st.session_state.authenticated:
    with st.sidebar:
        st.title("Detta")
        st.markdown("---")
        st.markdown(f"**Welcome, {st.session_state.user_name or st.session_state.user_email}!**", unsafe_allow_html=True)

        if st.session_state.current_page in ["login", "signup", "google_oauth_callback"]:
            st.session_state.current_page = "Upload"

        app_pages = ["Upload", "Clean", "Insights", "Visualize"]
        if st.session_state.current_page not in app_pages:
            st.session_state.current_page = "Upload"

        current_page_index = app_pages.index(st.session_state.current_page) if st.session_state.current_page in app_pages else 0

        selected_page_from_radio = st.radio(
            "Navigate", app_pages,
            index=current_page_index,
            key="main_nav_auth"
        )
        if selected_page_from_radio != st.session_state.current_page:
            st.session_state.current_page = selected_page_from_radio
            st.rerun()

        st.markdown("---")
        if st.session_state.api_key_valid is None and openai_client is None:
            st.session_state.openai_client = initialize_openai_client()
            st.session_state.api_key_valid = bool(st.session_state.openai_client)

        if st.session_state.api_key_valid:
            st.success("OpenAI API key valid.")
        else:
            st.error("Missing OpenAI API key. AI features disabled.")
            if st.button("Retry API Key Check", key="retry_api_auth"):
                st.session_state.openai_client = initialize_openai_client()
                st.session_state.api_key_valid = bool(st.session_state.openai_client)
                if st.session_state.api_key_valid:
                    app_logger.info("OpenAI API key re-check: Success")
                else:
                    app_logger.warning("OpenAI API key re-check: Failed")
                st.rerun()
        st.markdown("---")

        st.subheader("AI Assistant")
        if not st.session_state.api_key_valid:
            st.warning("AI chat disabled: No OpenAI API key.")
        else:
            with st.container():
                for chat_item in st.session_state.chat_history:
                    if chat_item.get("role") == "user" or "user" in chat_item:
                        st.markdown(f"<div class='chat-bubble-user'>You: {chat_item.get('user') or chat_item.get('content')}</div>", unsafe_allow_html=True)
                    elif chat_item.get("role") == "assistant" or "assistant" in chat_item:
                        st.markdown(f"<div class='chat-bubble-assistant'>Assistant: {chat_item.get('assistant') or chat_item.get('content')}</div>", unsafe_allow_html=True)

            user_chat_input = st.chat_input(
                "Ask a data question",
                key=f"chat_input_auth_{st.session_state.get('chat_reset_counter', 0)}"
            )

            if user_chat_input:
                df_for_chat = st.session_state.cleaned_df if st.session_state.cleaned_df is not None else st.session_state.df
                if df_for_chat is not None:
                    if st.session_state.get("is_dask") and hasattr(df_for_chat, 'compute'):
                        df_for_chat_pd = df_for_chat.compute()
                    else:
                        df_for_chat_pd = df_for_chat

                    with st.spinner("Thinking..."):
                        response = chat_with_gpt(df_for_chat_pd, user_chat_input, openai_client)
                    st.session_state.chat_history.append({"role": "user", "content": user_chat_input})
                    st.session_state.chat_history.append({"role": "assistant", "content": response})
                    st.session_state.chat_reset_counter = st.session_state.get('chat_reset_counter', 0) + 1
                    app_logger.info(f"User {st.session_state.user_email} asked: '{user_chat_input}'. Response: '{response[:50]}...'")
                    st.rerun()
                else:
                    st.warning("Please upload a dataset to chat about it.")

        st.markdown("---")
        if st.button("Log Out", key="logout_button", use_container_width=True):
            logout_user_email = st.session_state.user_email
            if st.session_state.jwt_token:
                with next(get_db()) as db:
                    delete_session(db, st.session_state.jwt_token)
            for key in list(st.session_state.keys()):
                if key not in ['logger', 'logger_initialized', 'openai_client', 'api_key_valid']:
                    del st.session_state[key]
            initialize_session_state()
            st.session_state.current_page = "login"
            html("<script>localStorage.removeItem('detta_jwt_token');</script>", height=0)
            app_logger.info(f"User {logout_user_email} logged out.")
            st.success("Logged out successfully.")
            st.rerun()

    with st.container():
        if st.session_state.current_page == "Upload":
            render_upload_page(openai_client)
        elif st.session_state.current_page == "Clean":
            render_clean_page(openai_client)
        elif st.session_state.current_page == "Insights":
            render_insights_page(openai_client)
        elif st.session_state.current_page == "Visualize":
            render_visualization_page(openai_client)

else:
    st.markdown('<div class="auth-container">', unsafe_allow_html=True)
    if st.session_state.current_page == "login":
        render_login_page()
    elif st.session_state.current_page == "signup":
        render_signup_page()
    elif st.session_state.current_page == "forgot_password":
        render_forgot_password_page()
    elif st.session_state.current_page == "reset_password":
        render_reset_password_page()
    elif st.session_state.current_page == "google_oauth_callback":
        st.info("Processing Google Sign-In... If this message persists, please try again.")
    else:
        app_logger.warning(f"Invalid page for unauthenticated user: {st.session_state.current_page}. Redirecting to login.")
        st.session_state.current_page = "login"
        st.query_params.clear()
        render_login_page()
    st.markdown('</div>', unsafe_allow_html=True)
