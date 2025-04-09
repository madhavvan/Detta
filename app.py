import streamlit as st
from ui import render_upload_page, render_clean_page, render_insights_page, render_visualization_page
from data_utils import chat_with_gpt, initialize_openai_client

st.set_page_config(page_title="Detta", layout="wide", initial_sidebar_state="expanded")

# Custom CSS for a polished look
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



# Initialize OpenAI client
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

# Page routing
with st.container():
    if page == "Upload":
        render_upload_page()
    elif page == "Clean":
        render_clean_page(openai_client)
    elif page == "Insights":
        render_insights_page(openai_client)
    elif page == "Visualize":
        render_visualization_page()

# Sidebar AI Chat Assistant
with st.sidebar:
    st.markdown("---")
    st.subheader("AI Assistant")
    if openai_client is None:
        st.warning("AI features disabled: No OpenAI API key.")
    else:
        user_input = st.chat_input("Ask a data question")
        if user_input and (st.session_state.df is not None or st.session_state.cleaned_df is not None):
            df_to_use = st.session_state.cleaned_df if st.session_state.cleaned_df is not None else st.session_state.df
            response = chat_with_gpt(df_to_use, user_input, openai_client)
            st.session_state.chat_history.append({"user": user_input, "assistant": response})
        for chat in st.session_state.chat_history:
            st.write(f"**You:** {chat['user']}")
            st.write(f"**Assistant:** {chat['assistant']}")