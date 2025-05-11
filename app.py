# app.py
"""
Main application file for Detta.
Handles page routing, authentication, and session management.
"""
import streamlit as st
from streamlit.runtime.scriptrunner import get_script_run_ctx # For logging session ID
import logging
from logging.handlers import RotatingFileHandler
import os
from datetime import datetime, timedelta, timezone
import uuid
from collections import deque
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# --- Module Imports ---
# Import UI rendering functions (original and new auth ones)
from ui import (
    render_login_page,
    render_signup_page,
    render_forgot_password_page,
    render_reset_password_page,
    handle_google_oauth_callback,
    render_upload_page_orig,  # Original upload page
    render_clean_page_orig,   # Original clean page
    render_insights_page_orig, # Original insights page
    render_visualization_page_orig, # Original visualization page
    get_query_params,
    set_page
)
# Import authentication and database utilities
from auth import verify_jwt_token, create_jwt_token, JWT_EXPIRATION_MINUTES, delete_session
from database import get_db, User, Session as DbSession, init_db as initialize_database, delete_expired_sessions

# Import existing Detta utilities (if they don't conflict or are managed within ui.py)
from data_utils import initialize_openai_client, chat_with_gpt, get_auto_suggestions

# --- Configuration ---
st.set_page_config(page_title="Detta", layout="wide", initial_sidebar_state="expanded")

# --- Custom CSS (Combined and refined) ---
st.markdown("""
    <style>
        /* General App Styles */
        .main { background-color: #f9f9f9; padding: 20px; border-radius: 10px; }
        h1, h2, h3 { color: #333; font-family: 'Arial', sans-serif; }
        .stButton>button {
            background-color: #4CAF50; /* Green */
            color: white;
            border-radius: 5px;
            font-size: 16px;
            padding: 10px 15px;
            border: none;
            cursor: pointer;
        }
        .stButton>button:hover { background-color: #45a049; }
        .stTextInput input, .stTextArea textarea {
            border: 1px solid #ccc;
            border-radius: 5px;
            padding: 10px;
        }
        .stAlert p { margin-bottom: 0; } /* Compact alerts */

        /* Sidebar */
        .sidebar .sidebar-content { background-color: #f0f0f0; padding: 15px; border-radius: 8px; }
        .sidebar .stRadio>label { font-size: 16px; color: #333; padding-top: 5px; padding-bottom: 5px;}
        .sidebar .stRadio>div[role="radiogroup"] > label { margin-bottom: 10px; } /* Space out radio buttons */

        /* DataFrames */
        .stDataFrame { border: 1px solid #ddd; border-radius: 5px; padding: 10px; }

        /* Chat Bubbles (from original app.py) */
        .chat-bubble-user { background-color: #d1e7dd; padding: 10px; border-radius: 8px 8px 0 8px; margin: 5px 0; float: right; clear: both; max-width: 70%; }
        .chat-bubble-assistant { background-color: #e9ecef; padding: 10px; border-radius: 8px 8px 8px 0; margin: 5px 0; float: left; clear: both; max-width: 70%;}
        .chat-container { overflow-y: auto; max-height: 300px; margin-bottom: 15px; } /* For scrollable chat */


        /* Auth Form Centering & Styling */
        div[data-testid="stVerticalBlock"] > div[style*="flex-direction: column;"] > div[data-testid="stVerticalBlock"] {
            /* This targets the column where auth forms are placed via st.columns([1,2,1]) */
            /* Add styling here if direct targeting is needed, but often better to wrap in a styled st.container */
        }
        .auth-container { /* You'd wrap your form columns in st.container(classname="auth-container") */
            max-width: 500px;
            margin: 2rem auto;
            padding: 2rem;
            background-color: #ffffff;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }

        /* Google Button (ensure this is consistent with ui.py) */
        .google-btn {
            display: inline-flex; align-items: center; justify-content: center;
            background-color: #4285F4; color: white !important; /* Important for specificity */
            padding: 10px 15px; border-radius: 5px; border: none;
            font-size: 16px; cursor: pointer; text-decoration: none;
            margin-bottom: 15px; width: 100%; /* Make it full width like other buttons */
        }
        .google-btn:hover { background-color: #357AE8; color: white !important; }
        .google-btn img { margin-right: 10px; width: 20px; height: 20px; }

        /* Password Strength Feedback (ensure consistent with ui.py) */
        .password-strength { font-size: 0.9em; margin-top: -10px; margin-bottom: 10px; text-align: left;}
        .password-strength.weak { color: #dc3545; } /* Bootstrap danger red */
        .password-strength.medium { color: #ffc107; } /* Bootstrap warning yellow */
        .password-strength.strong { color: #28a745; } /* Bootstrap success green */

        /* Accessibility: Focus indicators */
        *:focus {
            outline: 2px solid #4CAF50 !important; /* Green focus outline */
            outline-offset: 2px;
        }
        .stButton>button:focus-visible, .stTextInput input:focus-visible,
        .stSelectbox div[role="button"]:focus-visible, .stCheckbox input:focus-visible {
             box-shadow: 0 0 0 3px rgba(76, 175, 80, 0.5); /* Softer glow */
        }

    </style>
""", unsafe_allow_html=True)

# --- Logging Setup (User-Specific and Session-Specific) ---
# This needs to be initialized after potential user identification
def setup_logger():
    if 'logger_initialized' in st.session_state:
        return st.session_state.logger

    user_identifier = "anonymous"
    if st.session_state.get("authenticated") and st.session_state.get("user_email"):
        user_identifier = st.session_state.user_email.split('@')[0] # Example: user from user@example.com
    elif hasattr(st.runtime, 'scriptrunner') and hasattr(st.runtime.scriptrunner, 'get_script_run_ctx'): # Newer Streamlit
        ctx = st.runtime.scriptrunner.get_script_run_ctx()
        if ctx: user_identifier = f"session_{ctx.session_id[:8]}"
    else: # Fallback for older Streamlit or if ctx is None
         user_identifier = f"session_{uuid.uuid4().hex[:8]}"


    # Ensure logs directory exists (Streamlit Cloud compatible if /tmp/ is used, or if persistent storage is configured)
    # For Streamlit Cloud, writing to arbitrary paths isn't allowed. /tmp/ is usually fine.
    log_dir = "/tmp/detta_logs" # Recommended for Streamlit Cloud
    if not os.path.exists(log_dir):
        try:
            os.makedirs(log_dir)
        except OSError as e:
            print(f"Warning: Could not create log directory {log_dir}: {e}. Logging to current dir.")
            log_dir = "." # Fallback, might not work well in all environments

    log_file_name = f"detta_log_{user_identifier}_{datetime.now().strftime('%Y%m%d')}.log"
    log_file_path = os.path.join(log_dir, log_file_name)

    logger = logging.getLogger("DettaApp")
    logger.setLevel(logging.INFO)

    # Prevent adding multiple handlers on Streamlit reruns
    if not logger.handlers:
        handler = RotatingFileHandler(log_file_path, maxBytes=10*1024*1024, backupCount=3, encoding='utf-8')
        formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(module)s - %(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)

        # Optional: Add a Streamlit handler to show logs in UI for debugging (if desired)
        # class StreamlitLogHandler(logging.Handler):
        #     def emit(self, record):
        #         log_entry = self.format(record)
        #         st.session_state.app_logs.append(log_entry) # Assuming st.session_state.app_logs exists
        # stream_handler = StreamlitLogHandler()
        # stream_handler.setFormatter(formatter)
        # logger.addHandler(stream_handler)

    st.session_state.logger = logger
    st.session_state.logger_initialized = True
    logger.info(f"Logger initialized for {user_identifier}. Log file: {log_file_path}")
    return logger

# Initialize logger early
app_logger = setup_logger()


# --- Session State Initialization ---
def initialize_session_state():
    """Initializes all necessary session state variables."""
    defaults = {
        "authenticated": False,
        "user_id": None,
        "user_email": None,
        "user_name": "Guest",
        "jwt_token": None, # For persistent sessions across browser tabs (if implemented with cookies/localstorage)
        "current_page": "login", # Default page
        "last_activity": datetime.now(timezone.utc),
        "df": None,
        "cleaned_df": None,
        "chat_history": [], # User-specific
        "suggestions": [], # User-specific (cleaning suggestions)
        "vis_suggestions": [], # User-specific (visualization suggestions)
        "cleaning_history": deque(maxlen=5), # User-specific
        "pinned_chats": [], # User-specific
        "logs": [], # For app-specific operational logs shown in UI, not to be confused with file logs
        "onboarding_seen": False, # Potentially user-specific
        "api_key_valid": None, # Remains global or could be user-specific if they bring their own key
        "current_data_page": 0, # For paginating data displays
        "is_dask": False, # For DataFrame type tracking
        "app_logs": [], # For displaying logs in UI if desired
        "csrf_token": None # For CSRF protection
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value

    # Attempt to load user from JWT in session_state (e.g., if set by a previous run or cookie)
    # This part is more for web apps with actual persistent cookie/localstorage.
    # Streamlit's st.session_state is per browser tab & session.
    # However, we store the JWT from DB session for the current app interaction.
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
                # Optionally, refresh JWT if it's about to expire
                app_logger.info(f"User {user.email} re-authenticated via session JWT.")
            else: # Token invalid or expired
                st.session_state.jwt_token = None # Clear invalid token
                # delete_session(db, st.session_state.jwt_token) # Handled in verify_jwt_token
                app_logger.info("Invalid or expired session JWT found. Cleared.")
        finally:
            db_gen.close()


initialize_session_state()
app_logger = setup_logger() # Re-setup logger if user context changed after session init

# --- Database Initialization and Cleanup ---
try:
    initialize_database() # Creates tables if they don't exist
    with next(get_db()) as db: # Periodically clean expired sessions/tokens
        delete_expired_sessions(db)
        # delete_expired_password_reset_tokens(db) # Called in database.py example
except Exception as e:
    app_logger.error(f"Database initialization or cleanup error: {e}")
    st.error(f"A critical database error occurred: {e}. Some features might be unavailable.")


# --- OpenAI Client Initialization (from original app.py) ---
# This can remain global or be initialized after login if API keys are user-specific.
# For now, using existing global initialization.
if 'openai_client' not in st.session_state: # Initialize only once
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
    time_since_last_activity = datetime.now(timezone.utc) - st.session_state.last_activity
    if time_since_last_activity > timedelta(minutes=SESSION_TIMEOUT_MINUTES):
        app_logger.info(f"User {st.session_state.user_email} session timed out due to inactivity.")
        # Clear session from DB
        if st.session_state.jwt_token:
            with next(get_db()) as db:
                delete_session(db, st.session_state.jwt_token)
        # Reset Streamlit session state for auth
        st.session_state.authenticated = False
        st.session_state.user_id = None
        st.session_state.user_email = None
        st.session_state.user_name = "Guest"
        st.session_state.jwt_token = None
        st.session_state.current_page = "login" # Redirect to login
        st.warning("Your session has timed out due to inactivity. Please log in again.")
        st.rerun()
    else:
        # Update last activity time on any interaction (implicitly handled by rerun on action)
        # Or explicitly:
        st.session_state.last_activity = datetime.now(timezone.utc)


# --- Page Routing and Authentication Middleware ---
query_params = get_query_params()
page_param = query_params.get("page", [None])[0]
oauth_callback_code = query_params.get("code", [None])[0] # For Google OAuth

if page_param and page_param != st.session_state.current_page :
    # Allow navigation via URL parameter, e.g., for password reset link
    if page_param in ["login", "signup", "forgot_password", "reset_password", "google_oauth_callback"]:
         st.session_state.current_page = page_param
    elif st.session_state.authenticated and page_param in ["Upload", "Clean", "Insights", "Visualize"]:
        st.session_state.current_page = page_param
    # else: stay on current page or redirect to login if trying to access protected page unauth

# Handle Google OAuth Callback specifically
if st.session_state.current_page == "google_oauth_callback" or (oauth_callback_code and not st.session_state.authenticated):
    # The actual current_page might be 'login' if user directly hit the callback URL without starting flow
    # but 'code' in query_params is the key indicator for Google callback.
    st.session_state.current_page = "google_oauth_callback" # Ensure we are on this logical page
    handle_google_oauth_callback()
    # handle_google_oauth_callback will call set_page and rerun if successful.
    # If it's still on this page after the call, it means there was an error or it's processing.

# --- Sidebar and Main Content ---
if st.session_state.authenticated:
    # --- Authenticated User View ---
    with st.sidebar:
        st.title("Detta")
        st.markdown("---")
        if st.session_state.user_name and st.session_state.user_name != "Guest":
            st.write(f"Welcome, {st.session_state.user_name}!")
        else:
            st.write(f"Welcome, {st.session_state.user_email}!")

        # Navigation for authenticated users
        # Default to "Upload" if current_page is an auth page after login
        if st.session_state.current_page in ["login", "signup", "google_oauth_callback"]:
            st.session_state.current_page = "Upload"

        # Page navigation using radio buttons
        # Ensure current_page is valid, default to "Upload"
        app_pages = ["Upload", "Clean", "Insights", "Visualize"]
        if st.session_state.current_page not in app_pages:
            st.session_state.current_page = "Upload"

        # Use index to set default for radio if current_page comes from URL param
        current_page_index = app_pages.index(st.session_state.current_page) if st.session_state.current_page in app_pages else 0

        selected_page_from_radio = st.radio(
            "Navigate", app_pages,
            index=current_page_index,
            key="main_nav_auth"
        )
        if selected_page_from_radio != st.session_state.current_page:
             st.session_state.current_page = selected_page_from_radio
             # No set_page needed here, Streamlit's radio change handles rerun and updates current_page for content display

        st.markdown("---")
        # API Key Status (from original app.py)
        if st.session_state.api_key_valid is None and openai_client is None: # Check again
             st.session_state.openai_client = initialize_openai_client() # Attempt re-init
             st.session_state.api_key_valid = bool(st.session_state.openai_client)

        if st.session_state.api_key_valid:
            st.success("OpenAI API key valid.")
        else:
            st.error("Missing OpenAI API key. AI features disabled.")
            if st.button("Retry API Key Check", key="retry_api_auth"):
                st.session_state.openai_client = initialize_openai_client()
                st.session_state.api_key_valid = bool(st.session_state.openai_client)
                if st.session_state.api_key_valid: app_logger.info("OpenAI API key re-check: Success")
                else: app_logger.warning("OpenAI API key re-check: Failed")
                st.rerun()
        st.markdown("---")

        # AI Chat Assistant (from original app.py, needs user-specific chat_history)
        st.subheader("AI Assistant")
        if not st.session_state.api_key_valid:
            st.warning("AI chat disabled: No OpenAI API key.")
        else:
            # Display chat history (user-specific)
            # For simplicity, assuming st.session_state.chat_history is now correctly user-specific
            # It might be loaded from DB on login if it were persisted.
            # For now, it's in-memory per Streamlit session for the logged-in user.
            with st.container(): # Chat container for scrolling
                 # Chat history display (ensure it uses st.session_state.chat_history)
                for chat_item in st.session_state.chat_history:
                    if chat_item.get("role") == "user" or "user" in chat_item : # Compatibility
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
                    # Convert Dask to Pandas for chat_with_gpt if it expects pandas
                    if st.session_state.get("is_dask") and hasattr(df_for_chat, 'compute'):
                        df_for_chat_pd = df_for_chat.compute()
                    else:
                        df_for_chat_pd = df_for_chat

                    with st.spinner("Thinking..."):
                        response = chat_with_gpt(df_for_chat_pd, user_chat_input, openai_client) # Ensure chat_with_gpt takes client
                    st.session_state.chat_history.append({"role": "user", "content": user_chat_input})
                    st.session_state.chat_history.append({"role": "assistant", "content": response})
                    st.session_state.chat_reset_counter = st.session_state.get('chat_reset_counter', 0) + 1
                    app_logger.info(f"User {st.session_state.user_email} asked: '{user_chat_input}'. Response: '{response[:50]}...'")
                    st.rerun() # To update chat display
                else:
                    st.warning("Please upload a dataset to chat about it.")


        st.markdown("---")
        if st.button("Log Out", key="logout_button", use_container_width=True):
            logout_user_email = st.session_state.user_email
            # Clear session from DB
            if st.session_state.jwt_token:
                with next(get_db()) as db:
                    delete_session(db, st.session_state.jwt_token)

            # Reset Streamlit session state
            for key in list(st.session_state.keys()): # Iterate over a copy of keys
                if key not in ['logger', 'logger_initialized', 'openai_client', 'api_key_valid']: # Keep some global things
                    del st.session_state[key]
            initialize_session_state() # Re-initialize to defaults for logged-out state
            st.session_state.current_page = "login"
            app_logger.info(f"User {logout_user_email} logged out.")
            st.success("Logged out successfully.") # Show briefly before rerun
            st.rerun()

    # Main content area for authenticated users
    with st.container():
        if st.session_state.current_page == "Upload":
            render_upload_page_orig()
        elif st.session_state.current_page == "Clean":
            render_clean_page_orig(openai_client)
        elif st.session_state.current_page == "Insights":
            render_insights_page_orig(openai_client)
        elif st.session_state.current_page == "Visualize":
            render_visualization_page_orig(openai_client)
        # else: # Should not happen due to checks above
            # st.session_state.current_page = "Upload"
            # render_upload_page_orig()


else:
    # --- Unauthenticated User View (Login, Signup, Password Reset Pages) ---
    # Centered container for auth pages
    st.markdown('<div class="auth-container">', unsafe_allow_html=True)
    if st.session_state.current_page == "login":
        render_login_page()
    elif st.session_state.current_page == "signup":
        render_signup_page()
    elif st.session_state.current_page == "forgot_password":
        render_forgot_password_page()
    elif st.session_state.current_page == "reset_password":
        # This page expects a token in query_params
        render_reset_password_page()
    # Google OAuth callback is handled before this block if 'code' is present
    # Or if it was explicitly set as current_page
    elif st.session_state.current_page == "google_oauth_callback":
        # This state means it's likely still processing or errored before redirect
        # handle_google_oauth_callback() was already called if conditions met
        # If it's still here, display a message or let handle_google_oauth_callback manage it.
        st.info("Processing Google Sign-In... If this message persists, please try again.")
    else: # Default to login if current_page is invalid for unauthenticated user
        st.session_state.current_page = "login"
        render_login_page()
    st.markdown('</div>', unsafe_allow_html=True)


# --- Persisting user-specific st.session_state data ---
# This is a complex topic in Streamlit. True persistence across browser sessions
# usually means storing in the database and reloading on login.
# For data like `df`, `cleaned_df`, `chat_history`:
# Option 1: Store in DB (e.g., as JSON or pickled objects, linked to user_id).
#           - Pros: Full persistence.
#           - Cons: DB size, serialization/deserialization overhead, complexity.
# Option 2: Keep in st.session_state for the duration of the authenticated browser session.
#           - Pros: Simpler, faster for active session.
#           - Cons: Data lost when browser tab closes or session times out.
# The current implementation uses Option 2 primarily.
# To implement Option 1, you would:
#   - On login: Load user's data from DB into st.session_state.
#   - Periodically or on logout/page change: Save st.session_state data to DB.
# Example placeholder for saving:
# if st.session_state.authenticated and st.session_state.df is not None:
#     # This would be a function in database.py to save_user_dataframe(...)
#     # log.info(f"User data for {st.session_state.user_email} would be persisted here.")
#     pass
