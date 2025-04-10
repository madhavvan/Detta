# === IMPORTS ===
import streamlit as st
from ui import render_upload_page, render_clean_page, render_insights_page, render_visualization_page
from data_utils import initialize_openai_client, chat_with_gpt, get_auto_suggestions
from streamlit.runtime.scriptrunner import get_script_run_ctx
import logging
from logging.handlers import RotatingFileHandler
import os
from datetime import datetime

# === CONFIGURATION ===
st.set_page_config(page_title="Detta", layout="wide", initial_sidebar_state="expanded")

# Custom CSS for UX and accessibility
st.markdown("""
    <style>
    .main { background-color: #f9f9f9; padding: 20px; border-radius: 10px; }
    .stButton>button { background-color: #4CAF50; color: white; border-radius: 5px; font-size: 16px; }
    .stButton>button:hover { background-color: #45a049; }
    h1, h2, h3 { color: #333; font-family: 'Arial', sans-serif; }
    .sidebar .sidebar-content { background-color: #e0e0e0; padding: 10px; border-radius: 5px; }
    .stRadio>label { font-size: 16px; color: #333; }
    .stDataFrame { border: 1px solid #ddd; border-radius: 5px; padding: 10px; }
    .chat-bubble-user { background-color: #d1e7dd; padding: 10px; border-radius: 5px; margin: 5px 0; }
    .chat-bubble-assistant { background-color: #f0f0f0; padding: 10px; border-radius: 5px; margin: 5px 0; }
    </style>
""", unsafe_allow_html=True)

# === LOGGING SETUP ===
user_id = st.experimental_user.email if hasattr(st.experimental_user, 'email') else f"user_{get_script_run_ctx().session_id}"
log_file = f"detta_{user_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
handler = RotatingFileHandler(log_file, maxBytes=10*1024*1024, backupCount=5)
logging.basicConfig(level=logging.INFO, handlers=[handler], format="%(asctime)s - %(levelname)s - %(message)s")

# === SESSION STATE INITIALIZATION ===
if "df" not in st.session_state:
    st.session_state.df = None
if "cleaned_df" not in st.session_state:
    st.session_state.cleaned_df = None
if "chat_history" not in st.session_state:
    st.session_state.chat_history = []
if "suggestions" not in st.session_state:
    st.session_state.suggestions = []
if "logs" not in st.session_state:
    st.session_state.logs = []
if "vis_suggestions" not in st.session_state:
    st.session_state.vis_suggestions = []
if "chat_reset" not in st.session_state:
    st.session_state.chat_reset = 0
if "pinned_chats" not in st.session_state:
    st.session_state.pinned_chats = []
if "onboarding_seen" not in st.session_state:
    st.session_state.onboarding_seen = False
if "api_key_valid" not in st.session_state:
    st.session_state.api_key_valid = None

# === OPENAI CLIENT INITIALIZATION ===
openai_client = initialize_openai_client()
if openai_client:
    st.session_state.api_key_valid = True
    logging.info("OpenAI API key initialized successfully.")
else:
    st.session_state.api_key_valid = False
    logging.warning("OpenAI API key missing or invalid.")

# === SIDEBAR ===
with st.sidebar:
    st.title("Detta")
    st.markdown("---")
    page = st.radio("Navigate", ["Upload", "Clean", "Insights", "Visualize"], label_visibility="collapsed")

    # API Key Status
    if st.session_state.api_key_valid:
        st.success("API key valid")
    else:
        st.error("Missing API key. AI features disabled")
        if st.button("Retry", key="retry_api"):
            openai_client = initialize_openai_client()
            st.session_state.api_key_valid = bool(openai_client)
            st.rerun()

    # AI Chat Assistant
    st.markdown("---")
    st.subheader("AI Assistant")
    if not st.session_state.api_key_valid:
        st.warning("AI chat disabled: No API key.")
    else:
        if st.session_state.df is not None:
            auto_suggestions = get_auto_suggestions(st.session_state.df)
            selected_auto = st.selectbox("Quick Questions", [""] + auto_suggestions)
            if selected_auto:
                st.session_state.chat_input_value = selected_auto

        user_input = st.chat_input("Ask a data question", key=f"chat_input_{st.session_state.chat_reset}")
        if user_input and (st.session_state.df is not None or st.session_state.cleaned_df is not None):
            df_to_use = st.session_state.cleaned_df if st.session_state.cleaned_df is not None else st.session_state.df
            with st.spinner("Thinking..."):
                response = chat_with_gpt(df_to_use, user_input, openai_client)
                st.session_state.chat_history.append({"user": user_input, "assistant": response})
                st.session_state.chat_reset += 1
                st.toast("Response generated!", icon="🤖")

        # Chat History
        search_term = st.text_input("Search chat history")
        for i, chat in enumerate(st.session_state.chat_history):
            if not search_term or search_term.lower() in chat["user"].lower() or search_term.lower() in chat["assistant"].lower():
                st.markdown(f"<div class='chat-bubble-user'>You: {chat['user']}</div>", unsafe_allow_html=True)
                st.markdown(f"<div class='chat-bubble-assistant'>Assistant: {chat['assistant']}</div>", unsafe_allow_html=True)
                if st.button("Pin", key=f"pin_{i}"):
                    st.session_state.pinned_chats.append(chat)
                    st.toast("Message pinned!", icon="📌")

        # Pinned Messages
        if st.session_state.pinned_chats:
            st.markdown("---")
            st.subheader("Pinned Messages")
            for chat in st.session_state.pinned_chats:
                st.markdown(f"<div class='chat-bubble-user'>You: {chat['user']}</div>", unsafe_allow_html=True)
                st.markdown(f"<div class='chat-bubble-assistant'>Assistant: {chat['assistant']}</div>", unsafe_allow_html=True)

# === GUIDED TOUR ===
if not st.session_state.onboarding_seen:
    if st.button("Welcome to Detta!", key="tour_button"):
        with st.popover("Welcome to Detta!"):
            st.write("1. **Upload**: Start by uploading your CSV or Excel file.")
            st.write("2. **Clean**: Use manual tools or AI suggestions to refine your data.")
            st.write("3. **Explore**: Generate insights and visualize your dataset.")
            if st.button("Start Using Detta", key="start_tour"):
                st.session_state.onboarding_seen = True
                st.rerun()

# === PAGE ROUTING ===
with st.container():
    if page == "Upload":
        render_upload_page()
    elif page == "Clean":
        render_clean_page(openai_client)
    elif page == "Insights":
        render_insights_page(openai_client)
    elif page == "Visualize":
        render_visualization_page(openai_client)