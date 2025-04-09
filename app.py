import streamlit as st
from ui import render_upload_page, render_clean_page, render_insights_page, render_visualization_page
from data_utils import chat_with_gpt, initialize_openai_client

st.set_page_config(page_title="Detta", layout="wide", initial_sidebar_state="expanded")

# Initialize OpenAI client
openai_client = initialize_openai_client()

# Sidebar navigation
st.sidebar.title("Detta Navigation")
page = st.sidebar.radio("Go to", ["Upload", "Clean", "Insights", "Visualize"])

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
if page == "Upload":
    render_upload_page()
elif page == "Clean":
    render_clean_page(openai_client)
elif page == "Insights":
    render_insights_page(openai_client)
elif page == "Visualize":
    render_visualization_page()

# Sidebar AI Chat Assistant
st.sidebar.subheader("AI Chat Assistant")
if openai_client is None:
    st.sidebar.warning("AI features disabled: No OpenAI API key provided.")
else:
    user_input = st.sidebar.chat_input("Ask a data-related question")
    if user_input and (st.session_state.df is not None or st.session_state.cleaned_df is not None):
        df_to_use = st.session_state.cleaned_df if st.session_state.cleaned_df is not None else st.session_state.df
        response = chat_with_gpt(df_to_use, user_input, openai_client)
        st.session_state.chat_history.append({"user": user_input, "assistant": response})
    for chat in st.session_state.chat_history:
        st.sidebar.write(f"**You:** {chat['user']}")
        st.sidebar.write(f"**Assistant:** {chat['assistant']}")