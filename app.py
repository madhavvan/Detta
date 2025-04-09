import streamlit as st
import pandas as pd
from data_utils import initialize_openai_client, analyze_dataset, apply_selected_operations

# Custom CSS for professional UI
st.markdown("""
    <style>
    .main { background-color: #f5f6f5; padding: 20px; border-radius: 10px; }
    .stButton>button { background-color: #007bff; color: white; border-radius: 5px; padding: 8px 16px; }
    .stButton>button:hover { background-color: #0056b3; }
    h1, h2, h3 { color: #2c3e50; font-family: 'Helvetica', sans-serif; }
    .sidebar .sidebar-content { background-color: #ecf0f1; padding: 15px; border-radius: 5px; }
    .stCheckbox>label { font-size: 14px; color: #34495e; }
    .stDataFrame { border: 1px solid #bdc3c7; border-radius: 5px; padding: 10px; background-color: white; }
    .suggestion-box { margin: 10px 0; padding: 10px; background-color: #ffffff; border: 1px solid #e0e0e0; border-radius: 5px; }
    </style>
""", unsafe_allow_html=True)

st.set_page_config(page_title="Detta Pro", layout="wide", initial_sidebar_state="expanded")

# Initialize OpenAI client
openai_client = initialize_openai_client()

# Sidebar
with st.sidebar:
    st.title("Detta Pro")
    st.markdown("Advanced AI Dataset Enhancement")
    st.markdown("---")
    st.info("Upload your dataset to begin.")

# Main content
st.header("Detta Pro: Dataset Enhancement Tool")

# Dataset upload
uploaded_file = st.file_uploader("Upload CSV or Excel", type=["csv", "xlsx"], help="Max 200MB")
if uploaded_file:
    with st.spinner("Loading dataset..."):
        try:
            df = pd.read_csv(uploaded_file) if uploaded_file.name.endswith(".csv") else pd.read_excel(uploaded_file)
            st.session_state.df = df
            st.session_state.cleaned_df = None
            st.session_state.suggestions = None
            st.success(f"Dataset loaded: {df.shape[0]} rows, {df.shape[1]} columns")
        except Exception as e:
            st.error(f"Error loading file: {str(e)}")
    
    # Tabs for preview and enhancement
    tab1, tab2 = st.tabs(["Preview", "Enhance"])
    
    with tab1:
        st.subheader("Dataset Preview")
        st.dataframe(df.head(10), use_container_width=True)
    
    with tab2:
        st.subheader("Enhance Dataset")
        if openai_client and st.button("Analyze Dataset", key="analyze"):
            with st.spinner("Analyzing dataset with AI..."):
                suggestions = analyze_dataset(df, openai_client)
                st.session_state.suggestions = suggestions
        
        if "suggestions" in st.session_state and st.session_state.suggestions:
            st.markdown("### AI Suggestions")
            apply_all = st.checkbox("Apply All", key="apply_all")
            
            # Display suggestions
            actionable_suggestions = []
            for i, (suggestion, is_actionable) in enumerate(st.session_state.suggestions):
                with st.container():
                    if is_actionable:
                        key = f"sugg_{i}"
                        checked = st.checkbox(suggestion, value=apply_all, key=key)
                        actionable_suggestions.append((suggestion, checked))
                    else:
                        st.markdown(f"ℹ️ {suggestion}")
            
            # Apply selected operations
            if st.button("Apply Selected Enhancements", key="apply"):
                with st.spinner("Applying enhancements..."):
                    selected = [(sugg, True) for sugg, checked in actionable_suggestions if checked]
                    if selected:
                        cleaned_df = apply_selected_operations(df, selected)
                        st.session_state.cleaned_df = cleaned_df
                        st.success(f"Enhancements applied! New shape: {cleaned_df.shape}")
                    else:
                        st.warning("No enhancements selected.")
        
        # Display cleaned dataset
        if "cleaned_df" in st.session_state and st.session_state.cleaned_df is not None:
            st.markdown("---")
            st.subheader("Enhanced Dataset")
            view_option = st.radio("View", ["Preview (10 Rows)", "Full Dataset"], horizontal=True, key="view_enhance")
            with st.container():
                if view_option == "Preview (10 Rows)":
                    st.dataframe(st.session_state.cleaned_df.head(10), use_container_width=True)
                else:
                    st.dataframe(st.session_state.cleaned_df, use_container_width=True)