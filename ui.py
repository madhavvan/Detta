# ui.py
"""
Contains functions to render various UI pages for the Detta application,
including authentication pages (login, signup, password reset) and
existing application pages.
"""
import streamlit as st
import pandas as pd
# Ensure dask is handled if used, example shows it's used in original ui.py
try:
    import dask.dataframe as dd
except ImportError:
    dd = None # Fallback if dask is not installed or needed for auth pages

from openai import OpenAI # From original ui.py
from data_utils import (
    get_cleaning_suggestions,
    apply_cleaning_operations,
    get_insights,
    get_visualization_suggestions,
    get_dataset_summary
) # From original ui.py
from visualizations import render_chart # From original ui.py
import os # From original ui.py
import json # From original ui.py
from collections import deque # Ensure this is at the top of your app.py as well
from datetime import datetime, timedelta, timezone # Added timezone for consistency
import uuid # For password_reset_token UUID generation if needed elsewhere, good to have if related

from auth import (
    register_user_with_password,
    authenticate_user_with_password,
    get_google_oauth_flow,
    process_google_login,
    create_jwt_token,
    JWT_EXPIRATION_MINUTES, # Ensure this is used from auth or defined if needed directly
    initiate_password_reset,
    verify_and_reset_password,
    get_password_strength,
    generate_csrf_token,
    verify_csrf_token # We will use this
)
from database import get_db, create_session, User, get_password_reset_token # Added User and get_password_reset_token

# --- Helper for Page Navigation ---
def get_query_params():
    """Gets query parameters from Streamlit's URL."""
    return st.query_params.to_dict()

def set_page(page_name: str, params: dict = None):
    """Navigates to a different page, potentially with query parameters."""
    # Clear existing query parameters before setting new ones to avoid conflicts
    # This might be too aggressive depending on needs, but good for clean navigation
    keys_to_remove = list(st.query_params.keys())
    for key in keys_to_remove:
        st.query_params.pop(key)

    if params:
        st.query_params.from_dict(params)
    st.session_state.current_page = page_name
    st.rerun()


# --- Authentication UI Components ---

def render_login_page():
    """Renders the login page."""
    st.header("Log In to Detta")
    st.markdown( # Using existing CSS from previous versions
        """
        <style>
            .stAlert p { margin-bottom: 0; }
            .google-btn {
                display: inline-flex; align-items: center; justify-content: center;
                background-color: #4285F4; color: white !important; padding: 10px 15px;
                border-radius: 5px; border: none; font-size: 16px; cursor: pointer;
                text-decoration: none; margin-bottom: 10px; width: 100%;
            }
            .google-btn:hover { background-color: #357AE8; color: white !important; }
            .google-btn img { margin-right: 10px; width: 20px; height: 20px; }
        </style>
        """, unsafe_allow_html=True
    )

    # CSRF Token generated and stored in session_state
    csrf_token_value = generate_csrf_token()

    col1, col2, col3 = st.columns([1,2,1])

    with col2:
        google_flow = get_google_oauth_flow() # This might display an error if secrets aren't loaded
        if google_flow:
            auth_url, _ = google_flow.authorization_url(prompt='consent')
            st.markdown(
                f'<a href="{auth_url}" target="_self" class="google-btn"><img src="https://developers.google.com/identity/images/g-logo.png" alt="Google logo"> Sign in with Google</a>',
                unsafe_allow_html=True
            )
            st.markdown("<p style='text-align: center; margin-bottom: 15px;'>OR</p>", unsafe_allow_html=True)
        elif GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET: # Check if vars are loaded but flow failed
             pass # Error is shown by get_google_oauth_flow()
        else: # Secrets likely missing entirely
            st.warning("Google Sign-In is currently unavailable. Please ensure OAuth is configured correctly in app secrets if this is a deployed app.")


        with st.form("login_form"):
            email = st.text_input("Email", key="login_email", autocomplete="email", placeholder="your@email.com")
            password = st.text_input("Password", type="password", key="login_password", autocomplete="current-password")
            submitted = st.form_submit_button("Log In", use_container_width=True)

            if submitted:
                # Verify CSRF token from session state
                if not verify_csrf_token(csrf_token_value): # Pass the token generated for this page load
                    # verify_csrf_token shows its own error
                    st.rerun() # Stop processing if CSRF fails

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
                            # The jti (JWT ID) claim is often used to make tokens unique, e.g., for revocation.
                            # Here, we'll use the database session_id as the jti.
                            temp_jwt_token = create_jwt_token(data=jwt_payload) # Create a temporary token
                            expires_at = datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRATION_MINUTES)
                            
                            # Create DB session with a placeholder or the temp token first
                            db_session_obj = create_session(db, user_id=user.id, token="pending_jti", expires_at=expires_at)
                            
                            # Now add the actual session_id from the DB as jti into the payload
                            jwt_payload["jti"] = str(db_session_obj.session_id) 
                            final_jwt_token = create_jwt_token(data=jwt_payload) # Re-sign with jti
                            
                            db_session_obj.token = final_jwt_token # Update session in DB with the final token
                            db.commit()

                            st.session_state.jwt_token = final_jwt_token
                            st.success("Logged in successfully!")
                            if 'logger' in st.session_state and st.session_state.logger:
                                st.session_state.logger.info(f"User {user.email} logged in via password.")
                            set_page("Upload")
                        else:
                            st.error("Invalid email or password.")
                            if 'logger' in st.session_state and st.session_state.logger:
                                st.session_state.logger.warning(f"Failed login attempt for email: {email}")
                    finally:
                        db.close() # Correctly close the generator-based session

        st.markdown("---")
        col_signup, col_forgot = st.columns(2)
        with col_signup:
            if st.button("Don't have an account? Sign Up", key="goto_signup", use_container_width=True):
                set_page("signup")
        with col_forgot:
            if st.button("Forgot Password?", key="goto_forgot_password", use_container_width=True):
                set_page("forgot_password")

def render_signup_page():
    """Renders the signup page."""
    st.header("Sign Up for Detta")
    st.markdown( # Using existing CSS
        """
        <style>
            .stAlert p { margin-bottom: 0; }
            .google-btn { /* Style from login */ }
            .google-btn:hover { /* Style from login */ }
            .google-btn img { /* Style from login */ }
            .password-strength { font-size: 0.9em; margin-top: -10px; margin-bottom: 10px; text-align: left;}
            .password-strength.weak { color: #dc3545; }
            .password-strength.medium { color: #ffc107; }
            .password-strength.strong { color: #28a745; }
        </style>
        """, unsafe_allow_html=True
    )
    csrf_token_value = generate_csrf_token()
    col1, col2, col3 = st.columns([1,2,1])

    with col2:
        google_flow = get_google_oauth_flow()
        if google_flow:
            auth_url, _ = google_flow.authorization_url(prompt='consent')
            st.markdown(
                f'<a href="{auth_url}" target="_self" class="google-btn"><img src="https://developers.google.com/identity/images/g-logo.png" alt="Google logo"> Sign up with Google</a>',
                unsafe_allow_html=True
            )
            st.markdown("<p style='text-align: center; margin-bottom: 15px;'>OR</p>", unsafe_allow_html=True)
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
            submitted = st.form_submit_button("Sign Up", use_container_width=True)

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
        if st.button("Already have an account? Log In", key="goto_login_from_signup", use_container_width=True):
            set_page("login")


def render_forgot_password_page():
    """Renders the forgot password request page."""
    st.header("Forgot Password")
    csrf_token_value = generate_csrf_token()
    col1, col2, col3 = st.columns([1,2,1])

    with col2:
        with st.form("forgot_password_form"):
            email = st.text_input("Enter your email address", key="forgot_email", autocomplete="email")
            submitted = st.form_submit_button("Send Reset Link", use_container_width=True)

            if submitted:
                if not verify_csrf_token(csrf_token_value):
                    st.rerun()
                if not email:
                    st.error("Please enter your email address.")
                else:
                    db_gen = get_db()
                    db = next(db_gen)
                    try:
                        app_base_url = os.getenv("APP_BASE_URL", "http://localhost:8501") # Get from env
                        if "streamlit.app" in app_base_url and not app_base_url.startswith("https://"): # Ensure HTTPS for cloud
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
        if st.button("Back to Log In", key="back_to_login_from_forgot", use_container_width=True):
            set_page("login")

def render_reset_password_page():
    """Renders the page to enter a new password using a token."""
    st.header("Reset Your Password")
    csrf_token_value = generate_csrf_token()
    query_params = get_query_params()
    token_from_url = query_params.get("token", [None])[0]

    if not token_from_url:
        st.error("Invalid or missing password reset token in URL. Please use the link from your email.")
        if st.button("Request New Reset Link", key="request_new_from_reset"):
            set_page("forgot_password")
        return

    col1, col2, col3 = st.columns([1,2,1])
    with col2:
        with st.form("reset_password_form"):
            new_password = st.text_input("New Password", type="password", key="reset_new_password", autocomplete="new-password")
            confirm_password = st.text_input("Confirm New Password", type="password", key="reset_confirm_password", autocomplete="new-password")
            submitted = st.form_submit_button("Reset Password", use_container_width=True)

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
                                # Try to get email for logging before token is deleted
                                user_email_for_log = "unknown (token based)"
                                try:
                                    token_uuid = uuid.UUID(token_from_url)
                                    reset_token_obj_for_log = get_password_reset_token(db, token_uuid)
                                    if reset_token_obj_for_log and reset_token_obj_for_log.user:
                                        user_email_for_log = reset_token_obj_for_log.user.email
                                except ValueError:
                                    pass # Invalid UUID format for token
                                st.session_state.logger.info(f"Password successfully reset for user via token (email: {user_email_for_log}).")
                            
                            # Use st.query_params.clear() if available and appropriate, or set_page to login without token
                            set_page("login") # This will rerun and clear query_params by default due to set_page logic
                        else:
                            st.error(message)
                            if 'logger' in st.session_state and st.session_state.logger:
                                 st.session_state.logger.warning(f"Password reset attempt failed with token {token_from_url}: {message}")
                    finally:
                        db.close()

        st.markdown("---")
        if st.button("Back to Log In", key="back_to_login_from_reset_form", use_container_width=True):
            set_page("login")


# --- Google OAuth Callback Handler ---
def handle_google_oauth_callback():
    """Handles the redirect from Google OAuth."""
    st.info("Processing Google login...")
    query_params = get_query_params()
    code = query_params.get("code", [None])[0]
    error = query_params.get("error", [None])[0]

    # Clear Google OAuth specific query params to prevent reprocessing on rerun
    # Need to be careful not to clear other params if they exist and are needed.
    # A more robust way is for set_page to handle clearing query params.
    # For now, let's assume set_page will clear them after successful login.

    if error:
        st.error(f"Google OAuth Error: {error}. Please try logging in again.")
        if 'logger' in st.session_state and st.session_state.logger:
            st.session_state.logger.error(f"Google OAuth callback error: {error}")
        set_page("login") # Go back to login, this will clear params
        return

    if not code:
        # This might happen if user navigates away or refreshes during OAuth
        st.warning("Google OAuth callback incomplete. If you were trying to log in, please try again.")
        if 'logger' in st.session_state and st.session_state.logger:
            st.session_state.logger.warning("Google OAuth callback missing authorization code (potentially harmless refresh/nav).")
        # Don't automatically redirect to login here unless we're sure it's an error state vs. just a page refresh
        # If the page reloads without 'code', but they were authenticated, it's fine.
        # If they weren't authenticated, they'll stay on the auth pages.
        return # Allow current page logic in app.py to handle next steps

    db_gen = get_db()
    db = next(db_gen)
    try:
        user = process_google_login(code, db) # process_google_login uses the code
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
            st.success("Logged in successfully with Google!")
            if 'logger' in st.session_state and st.session_state.logger:
                st.session_state.logger.info(f"User {user.email} logged in via Google.")
            set_page("Upload") # Navigate to main app, this will clear query_params
        else:
            st.error("Failed to log in with Google. The authorization may have expired or there was an issue. Please try again or use email/password.")
            if 'logger' in st.session_state and st.session_state.logger:
                st.session_state.logger.error("process_google_login returned None during OAuth callback.")
            set_page("login") # Go back to login, this will clear query_params
    except Exception as e: # Catch any other unexpected errors during Google login processing
        st.error(f"An unexpected error occurred during Google sign-in: {e}")
        if 'logger' in st.session_state and st.session_state.logger:
            st.session_state.logger.error(f"Unexpected error in handle_google_oauth_callback: {e}", exc_info=True)
        set_page("login")
    finally:
        db.close()


# === EXISTING Detta UI functions (from user's ui.py) ===
# Assuming these are correctly defined and don't conflict with the new auth pages
# Make sure their dependencies are also correctly imported at the top of this file.
# For example, if they use 'deque', it should be imported. (It is now)

def render_upload_page_orig():
    """Render the upload page with lazy loading and progress."""
    st.header("Upload Dataset")
    col1, col2 = st.columns([3, 1])
    with col1:
        uploaded_file = st.file_uploader("Upload CSV or Excel (max 1GB)", type=["csv", "xlsx"], help="Supports CSV and Excel files up to 1GB.")
    with col2:
        st.write("File size limit: 1GB")

    if uploaded_file:
        file_size_mb = uploaded_file.size / (1024 * 1024)
        if file_size_mb > 1000: # As per original code
            st.error("File exceeds 1GB limit. Please upload a smaller file.")
            return

        with st.spinner("Loading dataset..."):
            progress_bar = st.progress(0)
            try:
                # Handle Dask if dd is available and file is large
                use_dask = dd is not None and file_size_mb > 50 # Check if dask is imported and file is large
                if use_dask:
                    # Simple chunking for CSV, for Excel it's more complex / might not support true chunking in read_excel easily
                    if uploaded_file.name.endswith(".csv"):
                        df_chunks = pd.read_csv(uploaded_file, chunksize=10000)
                        df = dd.from_pandas(pd.concat(df_chunks), npartitions=10) # Example npartitions
                    elif uploaded_file.name.endswith(".xlsx"):
                         # Dask doesn't directly read Excel in chunks like CSV. Load into pandas then convert.
                         # This might still be memory intensive for very large Excel files before dask conversion.
                        pandas_df = pd.read_excel(uploaded_file, engine='openpyxl')
                        df = dd.from_pandas(pandas_df, npartitions=10) # Example npartitions
                    else:
                        st.error("Unsupported file type for Dask processing in this example.")
                        return

                    # Simulate progress for Dask as it's lazy
                    for i in range(100): # Simple simulation
                        progress_bar.progress(i + 1, text=f"Processing ({(i+1)}%)") # Dask progress is harder to track directly
                    st.session_state.is_dask = True
                else:
                    df = pd.read_csv(uploaded_file) if uploaded_file.name.endswith(".csv") else pd.read_excel(uploaded_file, engine='openpyxl')
                    st.session_state.is_dask = False
                    progress_bar.progress(100, text="Upload complete!") # More accurate for pandas

                if st.session_state.is_dask: progress_bar.progress(100, text="Dask DataFrame created!")


                st.toast("Upload complete!", icon="✅")

                if df.empty or len(df.columns) == 0: # For dask, df.columns is available but df.empty needs compute()
                    is_empty = df.empty if not st.session_state.is_dask else df.map_partitions(lambda x: x.empty).compute().all()
                    if is_empty or len(df.columns) == 0 :
                        st.error("Empty file detected or no columns. Upload a valid CSV/Excel.")
                        return

                st.session_state.df = df
                st.session_state.cleaned_df = None
                st.session_state.suggestions = []
                st.session_state.cleaning_history = deque(maxlen=5)
                st.session_state.current_data_page = 0

                with st.expander("Dataset Summary", expanded=True):
                    current_df_for_summary = df.compute() if st.session_state.is_dask else df
                    summary = get_dataset_summary(current_df_for_summary)
                    st.write(summary)

                st.subheader("Dataset Preview")
                page_size = 10
                if st.session_state.is_dask:
                    # Dask specific pagination if needed, or compute a sample
                    total_rows = len(df) # For Dask, len(df) gives number of partitions if not computed, use df.index.size.compute()
                    # total_rows = df.index.size.compute() # This can be slow for very large Dask DFs just for pagination
                    st.dataframe(df.head(page_size), use_container_width=True, height=300) # Dask head is efficient
                else:
                    st.dataframe(df.head(page_size), use_container_width=True, height=300)

            except Exception as e:
                st.error(f"Error loading file: {str(e)}")
                if 'logger' in st.session_state and st.session_state.logger:
                    st.session_state.logger.error(f"Upload error: {str(e)}", exc_info=True)
                progress_bar.empty()


def render_clean_page_orig(openai_client: OpenAI | None):
    """Render the clean page."""
    if st.session_state.get("df") is None:
        st.warning("Please upload a dataset on the Upload page.")
        if st.button("Go to Upload Page"):
            set_page("Upload")
        return

    st.header("Clean Dataset")
    # Work with a copy for display/operations to not alter original session state df unknowingly
    current_df_display = st.session_state.get("cleaned_df", st.session_state.df)
    is_dask_current = st.session_state.get("is_dask", False) if st.session_state.get("cleaned_df") is None else isinstance(current_df_display, dd.DataFrame if dd else type(None))


    col1, col2 = st.columns([2, 1])
    with col1:
        st.subheader("Current Dataset Preview")
        display_sample = current_df_display.head(10)
        if is_dask_current : display_sample = display_sample.compute()
        st.dataframe(display_sample, use_container_width=True, height=300)

    with col2:
        st.subheader("Cleaning Actions")
        with st.expander("Manual Cleaning", expanded=False):
            # Get columns from the correct dataframe (original df for available columns)
            original_df_columns = st.session_state.df.columns
            if st.session_state.get("is_dask", False) : original_df_columns = original_df_columns.compute()

            columns_to_drop = st.multiselect("Drop columns", original_df_columns, key="clean_drop_cols")
            replace_value = st.text_input("Replace value (e.g., '?')", key="clean_replace_val")
            replace_with = st.text_input("With (e.g., 'NaN' for missing)", key="clean_replace_with")

        if openai_client and st.button("Get AI Suggestions", help="Fetch AI-driven cleaning suggestions", key="clean_get_ai_sugg"):
            with st.spinner("Generating AI suggestions..."):
                # AI suggestions should ideally work on a pandas sample for speed, or full if necessary
                df_for_ai = current_df_display.head(1000).compute() if is_dask_current else current_df_display.head(1000) # Use a sample
                suggestions = get_cleaning_suggestions(df_for_ai, openai_client)
                st.session_state.suggestions = suggestions
                st.toast("Suggestions generated!", icon="🤖")

        if st.session_state.get("suggestions"):
            with st.expander("AI Suggestions", expanded=True):
                for i, (suggestion, reason, confidence) in enumerate(st.session_state.suggestions):
                    st.checkbox(f"{suggestion} - {reason} (Confidence: {confidence*100:.0f}%)", key=f"sugg_{i}")
                    if confidence < 0.5:
                        st.warning(f"Low confidence suggestion: {suggestion}")

    # df_for_ops should be the current state of data (cleaned_df or original df)
    df_to_operate_on = st.session_state.get("cleaned_df", st.session_state.df)
    is_dask_to_operate = st.session_state.get("is_dask", False) if st.session_state.get("cleaned_df") is None else isinstance(df_to_operate_on, dd.DataFrame if dd else type(None))


    if st.button("Apply Selected Changes", help="Execute selected manual and AI cleaning steps", key="clean_apply_selected"):
        selected_ai_suggestions = [sugg for i, sugg in enumerate(st.session_state.get("suggestions", [])) if st.session_state.get(f"sugg_{i}", False)]

        # For Dask, operations need to be Dask-compatible or compute first.
        # apply_cleaning_operations should ideally handle Dask or take pandas.
        # Assuming apply_cleaning_operations expects pandas for now or handles Dask internally.
        df_input_for_apply = df_to_operate_on.compute() if is_dask_to_operate else df_to_operate_on.copy()

        with st.spinner("Applying cleaning operations..."):
            try:
                cleaned_df_result_pd, logs = apply_cleaning_operations(
                    df_input_for_apply,
                    selected_ai_suggestions,
                    columns_to_drop, # From manual section
                    replace_value,   # From manual section
                    replace_with     # From manual section
                )

                if not cleaned_df_result_pd.equals(df_input_for_apply): # Check if actual changes were made
                    # Store previous state for undo
                    # Decide if cleaned_df should remain Dask or become Pandas
                    # For simplicity here, we'll assume it becomes Pandas.
                    # If Dask workflow is critical, apply_cleaning_operations would need to return a Dask DF.
                    st.session_state.cleaning_history.append(
                        (st.session_state.get("cleaned_df"), # Store previous cleaned_df state
                         f"Step {len(st.session_state.cleaning_history) + 1}: Applied selected changes")
                    )
                    st.session_state.cleaned_df = cleaned_df_result_pd
                    st.session_state.is_dask = False # Result is now pandas
                    st.toast(f"Cleaning applied! New shape: {cleaned_df_result_pd.shape}", icon="✅")
                    # Log operations
                    if 'logger' in st.session_state and st.session_state.logger:
                        st.session_state.logger.info(f"Cleaning applied: {logs}")
                    st.rerun() # Rerun to show updated "Current Dataset Preview"
                else:
                    st.warning("No changes were made to the dataset based on selections.")
            except Exception as e:
                st.error(f"Error applying cleaning: {str(e)}")
                if 'logger' in st.session_state and st.session_state.logger:
                    st.session_state.logger.error(f"Error applying cleaning: {str(e)}", exc_info=True)


    if st.session_state.get("cleaned_df") is not None:
        st.markdown("---")
        st.subheader("Cleaned Dataset Preview")
        # This will now show the result of st.session_state.cleaned_df
        final_cleaned_df = st.session_state.cleaned_df # Which is pandas now
        st.dataframe(final_cleaned_df.head(10), use_container_width=True, height=300)


def render_insights_page_orig(openai_client: OpenAI | None):
    """Render the insights page."""
    if st.session_state.get("df") is None:
        st.warning("Please upload a dataset first.")
        if st.button("Go to Upload Page"):
            set_page("Upload")
        return

    st.header("Insights")
    df_for_insights = st.session_state.get("cleaned_df", st.session_state.get("df"))
    is_dask_insights = isinstance(df_for_insights, dd.DataFrame if dd else type(None))


    display_sample_insights = df_for_insights.head(10)
    if is_dask_insights : display_sample_insights = display_sample_insights.compute()
    st.dataframe(display_sample_insights, use_container_width=True, height=300)

    if openai_client and st.button("Generate Insights", help="Get AI-driven insights", key="insights_generate"):
        with st.spinner("Analyzing dataset..."):
            pd_df_for_insights = df_for_insights.compute() if is_dask_insights else df_for_insights
            insights_list = get_insights(pd_df_for_insights) # get_insights should take client if needed by its new def
            st.session_state.generated_insights = insights_list # Store in session state
            st.toast("Insights generated!", icon="📊")

    if st.session_state.get("generated_insights"):
        st.subheader("Key Insights")
        for i, insight_text in enumerate(st.session_state.generated_insights):
            st.markdown(f"- {insight_text}")
            # Add button to visualize or explore insight if desired


def render_visualization_page_orig(openai_client: OpenAI | None):
    """Render the visualization page."""
    if st.session_state.get("df") is None:
        st.warning("Please upload a dataset first.")
        if st.button("Go to Upload Page"):
            set_page("Upload")
        return

    st.header("Visualize Data")
    df_for_viz = st.session_state.get("cleaned_df", st.session_state.get("df"))
    is_dask_viz = isinstance(df_for_viz, dd.DataFrame if dd else type(None))

    if openai_client and st.button("Suggest Visualizations", help="Get AI visualization suggestions", key="viz_suggest"):
        with st.spinner("Generating visualization suggestions..."):
            # Pass pandas DataFrame to suggestion function
            pd_df_for_viz = df_for_viz.compute() if is_dask_viz else df_for_viz
            suggestions = get_visualization_suggestions(pd_df_for_viz) # Pass client if new def needs it
            st.session_state.vis_suggestions = suggestions
            st.toast("Visualization suggestions ready!", icon="📈")

    if "vis_suggestions" in st.session_state and st.session_state.vis_suggestions:
        st.subheader("AI Visualization Suggestions")
        # Ensure suggestions have the expected structure
        valid_suggestions = [s for s in st.session_state.vis_suggestions if isinstance(s, dict) and "description" in s]
        if not valid_suggestions:
            st.warning("No valid visualization suggestions available in the expected format.")
        else:
            selected_desc = st.selectbox("Choose a suggestion", [s["description"] for s in valid_suggestions], key="viz_select_sugg")
            if selected_desc:
                vis_config = next((s for s in valid_suggestions if s["description"] == selected_desc), None)
                if vis_config and all(k in vis_config for k in ["chart_type", "x", "y"]):
                    # Ensure df passed to render_chart is Pandas
                    df_to_plot = df_for_viz.compute() if is_dask_viz else df_for_viz
                    render_chart(df_to_plot, vis_config["chart_type"], vis_config["x"], vis_config["y"])
                else:
                    st.error("Selected visualization suggestion is missing necessary configuration details (chart_type, x, y).")
    else:
        # Default manual chart rendering if no AI suggestions are present or chosen
        df_to_plot = df_for_viz.compute() if is_dask_viz else df_for_viz
        render_chart(df_to_plot) # render_chart in visualizations.py should handle defaults


# Placeholders for GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET if not loaded from .env for some reason
# This allows the UI to render without immediately crashing if secrets are missing,
# though functionality will be impaired. The get_google_oauth_flow() will show an error.
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")