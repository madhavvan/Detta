# ui.py
"""
Contains functions to render various UI pages for the Detta application,
including authentication pages (login, signup, password reset) and
existing application pages.
"""
import streamlit as st
from streamlit.components.v1 import html  # For injecting JavaScript
import pandas as pd
try:
    import dask.dataframe as dd
except ImportError:
    dd = None

from openai import OpenAI
from data_utils import (
    get_cleaning_suggestions,
    apply_cleaning_operations,
    get_insights,
    get_visualization_suggestions,
    get_dataset_summary
)
from visualizations import render_chart
import os
import json
from collections import deque
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

    csrf_token_value = generate_csrf_token()
    col1, col2, col3 = st.columns([1, 2, 1])

    with col2:
        google_flow = get_google_oauth_flow()
        if google_flow:
            auth_url, _ = google_flow.authorization_url(prompt='consent')
            st.markdown(
                f'<a href="{auth_url}" target="_self" class="google-btn"><img src="https://developers.google.com/identity/images/g-logo.png" alt="Google logo"> Sign in with Google</a>',
                unsafe_allow_html=True
            )
            st.markdown("<p style='text-align: center; margin-bottom: 15px;'>OR</p>", unsafe_allow_html=True)
        elif GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET:
            pass
        else:
            st.warning("Google Sign-In is currently unavailable.")

        with st.form("login_form"):
            email = st.text_input("Email", key="login_email", autocomplete="email", placeholder="your@email.com")
            password = st.text_input("Password", type="password", key="login_password", autocomplete="current-password")
            submitted = st.form_submit_button("Log In", use_container_width=True)

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
                            # Save token to localStorage
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
            if st.button("Don't have an account? Sign Up", key="goto_signup", use_container_width=True):
                set_page("signup")
        with col_forgot:
            if st.button("Forgot Password?", key="goto_forgot_password", use_container_width=True):
                set_page("forgot_password")

def render_signup_page():
    """Renders the signup page."""
    st.header("Sign Up for Detta")
    st.markdown(
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
    col1, col2, col3 = st.columns([1, 2, 1])

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
    col1, col2, col3 = st.columns([1, 2, 1])

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

    col1, col2, col3 = st.columns([1, 2, 1])
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
        if st.button("Back to Log In", key="back_to_login_from_reset_form", use_container_width=True):
            set_page("login")

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
            # Save token to localStorage
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

# --- Existing Detta UI Functions ---
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
        if file_size_mb > 1000:
            st.error("File exceeds 1GB limit. Please upload a smaller file.")
            return

        with st.spinner("Loading dataset..."):
            progress_bar = st.progress(0)
            try:
                use_dask = dd is not None and file_size_mb > 50
                if use_dask:
                    if uploaded_file.name.endswith(".csv"):
                        df_chunks = pd.read_csv(uploaded_file, chunksize=10000)
                        df = dd.from_pandas(pd.concat(df_chunks), npartitions=10)
                    elif uploaded_file.name.endswith(".xlsx"):
                        pandas_df = pd.read_excel(uploaded_file, engine='openpyxl')
                        df = dd.from_pandas(pandas_df, npartitions=10)
                    else:
                        st.error("Unsupported file type for Dask processing.")
                        return
                    for i in range(100):
                        progress_bar.progress(i + 1, text=f"Processing ({(i+1)}%)")
                    st.session_state.is_dask = True
                else:
                    df = pd.read_csv(uploaded_file) if uploaded_file.name.endswith(".csv") else pd.read_excel(uploaded_file, engine='openpyxl')
                    st.session_state.is_dask = False
                    progress_bar.progress(100, text="Upload complete!")

                if st.session_state.is_dask:
                    progress_bar.progress(100, text="Dask DataFrame created!")

                st.toast("Upload complete!", icon="✅")

                if df.empty or len(df.columns) == 0:
                    is_empty = df.empty if not st.session_state.is_dask else df.map_partitions(lambda x: x.empty).compute().all()
                    if is_empty or len(df.columns) == 0:
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
                    st.dataframe(df.head(page_size), use_container_width=True, height=300)
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
    current_df_display = st.session_state.get("cleaned_df", st.session_state.df)
    is_dask_current = st.session_state.get("is_dask", False) if st.session_state.get("cleaned_df") is None else isinstance(current_df_display, dd.DataFrame if dd else type(None))

    col1, col2 = st.columns([2, 1])
    with col1:
        st.subheader("Current Dataset Preview")
        display_sample = current_df_display.head(10)
        if is_dask_current:
            display_sample = display_sample.compute()
        st.dataframe(display_sample, use_container_width=True, height=300)

    with col2:
        st.subheader("Cleaning Actions")
        with st.expander("Manual Cleaning", expanded=False):
            original_df_columns = st.session_state.df.columns
            if st.session_state.get("is_dask", False):
                original_df_columns = original_df_columns.compute()

            columns_to_drop = st.multiselect("Drop columns", original_df_columns, key="clean_drop_cols")
            replace_value = st.text_input("Replace value (e.g., '?')", key="clean_replace_val")
            replace_with = st.text_input("With (e.g., 'NaN' for missing)", key="clean_replace_with")

        if openai_client and st.button("Get AI Suggestions", help="Fetch AI-driven cleaning suggestions", key="clean_get_ai_sugg"):
            with st.spinner("Generating AI suggestions..."):
                df_for_ai = current_df_display.head(1000).compute() if is_dask_current else current_df_display.head(1000)
                suggestions = get_cleaning_suggestions(df_for_ai, openai_client)
                st.session_state.suggestions = suggestions
                st.toast("Suggestions generated!", icon="🤖")

        if st.session_state.get("suggestions"):
            with st.expander("AI Suggestions", expanded=True):
                for i, (suggestion, reason, confidence) in enumerate(st.session_state.suggestions):
                    st.checkbox(f"{suggestion} - {reason} (Confidence: {confidence*100:.0f}%)", key=f"sugg_{i}")
                    if confidence < 0.5:
                        st.warning(f"Low confidence suggestion: {suggestion}")

    df_to_operate_on = st.session_state.get("cleaned_df", st.session_state.df)
    is_dask_to_operate = st.session_state.get("is_dask", False) if st.session_state.get("cleaned_df") is None else isinstance(df_to_operate_on, dd.DataFrame if dd else type(None))

    if st.button("Apply Selected Changes", help="Execute selected manual and AI cleaning steps", key="clean_apply_selected"):
        selected_ai_suggestions = [sugg for i, sugg in enumerate(st.session_state.get("suggestions", [])) if st.session_state.get(f"sugg_{i}", False)]
        df_input_for_apply = df_to_operate_on.compute() if is_dask_to_operate else df_to_operate_on.copy()

        with st.spinner("Applying cleaning operations..."):
            try:
                cleaned_df_result_pd, logs = apply_cleaning_operations(
                    df_input_for_apply,
                    selected_ai_suggestions,
                    columns_to_drop,
                    replace_value,
                    replace_with
                )
                if not cleaned_df_result_pd.equals(df_input_for_apply):
                    st.session_state.cleaning_history.append(
                        (st.session_state.get("cleaned_df"),
                         f"Step {len(st.session_state.cleaning_history) + 1}: Applied selected changes")
                    )
                    st.session_state.cleaned_df = cleaned_df_result_pd
                    st.session_state.is_dask = False
                    st.toast(f"Cleaning applied! New shape: {cleaned_df_result_pd.shape}", icon="✅")
                    if 'logger' in st.session_state and st.session_state.logger:
                        st.session_state.logger.info(f"Cleaning applied: {logs}")
                    st.rerun()
                else:
                    st.warning("No changes were made to the dataset based on selections.")
            except Exception as e:
                st.error(f"Error applying cleaning: {str(e)}")
                if 'logger' in st.session_state and st.session_state.logger:
                    st.session_state.logger.error(f"Error applying cleaning: {str(e)}", exc_info=True)

    if st.session_state.get("cleaned_df") is not None:
        st.markdown("---")
        st.subheader("Cleaned Dataset Preview")
        final_cleaned_df = st.session_state.cleaned_df
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
    if is_dask_insights:
        display_sample_insights = display_sample_insights.compute()
    st.dataframe(display_sample_insights, use_container_width=True, height=300)

    if openai_client and st.button("Generate Insights", help="Get AI-driven insights", key="insights_generate"):
        with st.spinner("Analyzing dataset..."):
            pd_df_for_insights = df_for_insights.compute() if is_dask_insights else df_for_insights
            insights_list = get_insights(pd_df_for_insights)
            st.session_state.generated_insights = insights_list
            st.toast("Insights generated!", icon="📊")

    if st.session_state.get("generated_insights"):
        st.subheader("Key Insights")
        for i, insight_text in enumerate(st.session_state.generated_insights):
            st.markdown(f"- {insight_text}")

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
            pd_df_for_viz = df_for_viz.compute() if is_dask_viz else df_for_viz
            suggestions = get_visualization_suggestions(pd_df_for_viz)
            st.session_state.vis_suggestions = suggestions
            st.toast("Visualization suggestions ready!", icon="📈")

    if "vis_suggestions" in st.session_state and st.session_state.vis_suggestions:
        st.subheader("AI Visualization Suggestions")
        valid_suggestions = [s for s in st.session_state.vis_suggestions if isinstance(s, dict) and "description" in s]
        if not valid_suggestions:
            st.warning("No valid visualization suggestions available in the expected format.")
        else:
            selected_desc = st.selectbox("Choose a suggestion", [s["description"] for s in valid_suggestions], key="viz_select_sugg")
            if selected_desc:
                vis_config = next((s for s in valid_suggestions if s["description"] == selected_desc), None)
                if vis_config and all(k in vis_config for k in ["chart_type", "x", "y"]):
                    df_to_plot = df_for_viz.compute() if is_dask_viz else df_for_viz
                    render_chart(df_to_plot, vis_config["chart_type"], vis_config["x"], vis_config["y"])
                else:
                    st.error("Selected visualization suggestion is missing necessary configuration details (chart_type, x, y).")
    else:
        df_to_plot = df_for_viz.compute() if is_dask_viz else df_for_viz
        render_chart(df_to_plot)

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
