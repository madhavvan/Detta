import streamlit as st
from ui import render_upload_page, render_clean_page, render_insights_page, render_visualization_page
from data_utils import chat_with_gpt, initialize_openai_client, get_auto_suggestions
import asyncio
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, filename="detta.log")

st.set_page_config(page_title="Detta", layout="wide", initial_sidebar_state="expanded")

# Custom CSS
st.markdown("""
    <style>
    .main { background-color: #f9f9f9; padding: 20px; border-radius: 10px; }
    .stButton>button { background-color: #4CAF50; color: white; border-radius: 5px; }
    .stButton>button:hover { background-color: #45a049; }
    h1, h2, h3 { color: #333; font-family: 'Arial', sans-serif; }
    .sidebar .sidebar-content { background-color: #e0e0e0; padding: 10px; border-radius: 5px; }
    .stRadio>label { font-size: 16px; }
    .stDataFrame { border: 1px solid #ddd; border-radius: 5px; padding: 10px; }
    </style>
""", unsafe_allow_html=True)

# Onboarding popup
if "onboarding_seen" not in st.session_state:
    with st.expander("Welcome to Detta!", expanded=True):
        st.write("1. Upload a CSV/Excel file.\n2. Clean your data manually or with AI.\n3. Gain insights and visualize.\n4. Chat with the AI assistant!")
        if st.button("Got it!"):
            st.session_state.onboarding_seen = True

# Initialize OpenAI client without caching
openai_client = initialize_openai_client()

# Sidebar navigation
with st.sidebar:
    st.title("Detta")
    st.markdown("---")
    page = st.radio("Navigate", ["Upload", "Clean", "Insights", "Visualize"], label_visibility="collapsed")

# Initialize session state
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
    st.session_state.chat_reset = 0  # Counter to reset chat input

# Page routing
with st.container():
    if page == "Upload":
        render_upload_page()
    elif page == "Clean":
        render_clean_page(openai_client)
    elif page == "Insights":
        render_insights_page(openai_client)
    elif page == "Visualize":
        render_visualization_page(openai_client)

# Sidebar AI Chat Assistant
with st.sidebar:
    st.markdown("---")
    st.subheader("AI Assistant")
    if openai_client is None:
        st.warning("AI features disabled: No OpenAI API key.")
    else:
        # Auto-suggestions
        if st.session_state.df is not None:
            auto_suggestions = get_auto_suggestions(st.session_state.df)
            selected_auto = st.selectbox("Quick Questions", [""] + auto_suggestions)
            if selected_auto:
                st.session_state.chat_input_value = selected_auto

        # Use a unique key to reset chat input
        user_input = st.chat_input("Ask a data question", key=f"chat_input_{st.session_state.chat_reset}")
        if user_input and (st.session_state.df is not None or st.session_state.cleaned_df is not None):
            df_to_use = st.session_state.cleaned_df if st.session_state.cleaned_df is not None else st.session_state.df
            with st.spinner("Thinking..."):
                async def get_response():
                    return chat_with_gpt(df_to_use, user_input, openai_client)
                response = asyncio.run(get_response())
                st.session_state.chat_history.append({"user": user_input, "assistant": response})
                st.session_state.chat_reset += 1  # Increment to reset input

        # Interactive chat history
        search_term = st.text_input("Search chat history")
        for chat in st.session_state.chat_history:
            if not search_term or search_term.lower() in chat["user"].lower() or search_term.lower() in chat["assistant"].lower():
                st.write(f"**You:** {chat['user']}")
                st.write(f"**Assistant:** {chat['assistant']}")