import streamlit as st
import pandas as pd
from data_utils import get_cleaning_suggestions, apply_cleaning_operations, get_insights
from visualizations import render_bar_chart

def render_upload_page():
    st.header("Upload Dataset")
    col1, col2 = st.columns([3, 1])
    with col1:
        uploaded_file = st.file_uploader("Upload CSV or Excel (max 200MB)", type=["csv", "xlsx"], help="Supports CSV and Excel files.")
    with col2:
        st.write("")  # Spacer
        st.write("File size limit: 200MB")
    if uploaded_file:
        with st.spinner("Loading dataset..."):
            try:
                if uploaded_file.name.endswith(".csv"):
                    df = pd.read_csv(uploaded_file)
                else:
                    df = pd.read_excel(uploaded_file)
                st.session_state.df = df
                st.session_state.cleaned_df = None
                st.session_state.suggestions = []
                st.success(f"Loaded {uploaded_file.name} successfully!")
                st.subheader("Dataset Preview")
                st.dataframe(df.head(10), use_container_width=True)
            except Exception as e:
                st.error(f"Error: {str(e)}")

def render_clean_page(openai_client):
    if st.session_state.df is None:
        st.warning("Please upload a dataset on the Upload page.")
        return
    st.header("Clean Dataset")
    df = st.session_state.df
    
    # Two-column layout for preview and actions
    col1, col2 = st.columns([2, 1])
    with col1:
        st.subheader("Original Preview")
        st.dataframe(df.head(10), use_container_width=True)
    with col2:
        st.subheader("Cleaning Actions")
        with st.expander("Manual Cleaning", expanded=False):
            columns_to_drop = st.multiselect("Drop columns", df.columns)
            replace_value = st.text_input("Replace value (e.g., '?')")
            replace_with = st.text_input("With (e.g., 'NaN')")
        if openai_client and st.button("Get AI Suggestions"):
            with st.spinner("Generating AI suggestions..."):
                suggestions = get_cleaning_suggestions(df, openai_client)
                st.session_state.suggestions = suggestions
                st.success("Suggestions generated!")
        if st.session_state.suggestions:
            with st.expander("AI Suggestions", expanded=True):
                for i, (suggestion, reason) in enumerate(st.session_state.suggestions):
                    st.checkbox(f"{suggestion} ({reason})", key=f"sugg_{i}")

    # Apply cleaning button at the bottom
    if st.button("Apply Cleaning", use_container_width=True):
        selected_suggestions = [sugg for i, sugg in enumerate(st.session_state.suggestions) if st.session_state.get(f"sugg_{i}", False)]
        with st.spinner("Applying cleaning operations..."):
            cleaned_df = apply_cleaning_operations(df, selected_suggestions, columns_to_drop, replace_value, replace_with)
            st.session_state.cleaned_df = cleaned_df
            st.success(f"Cleaning applied! New shape: {cleaned_df.shape}")

    # Display cleaned data
    if "cleaned_df" in st.session_state and st.session_state.cleaned_df is not None:
        st.markdown("---")
        st.subheader("Cleaned Dataset")
        view_option = st.radio("View", ["Preview (10 Rows)", "Full Dataset"], horizontal=True, key="view_clean")
        with st.container():
            if view_option == "Preview (10 Rows)":
                st.dataframe(st.session_state.cleaned_df.head(10), use_container_width=True)
            else:
                st.dataframe(st.session_state.cleaned_df, use_container_width=True)

def render_insights_page(openai_client):
    if st.session_state.df is None:
        st.warning("Please upload a dataset first.")
        return
    st.header("Insights")
    df = st.session_state.cleaned_df if st.session_state.cleaned_df is not None else st.session_state.df
    st.dataframe(df.head(10), use_container_width=True)
    if openai_client and st.button("Generate Insights"):
        with st.spinner("Analyzing dataset..."):
            insights = get_insights(df, openai_client)
            st.subheader("Key Insights")
            for insight in insights:
                st.markdown(f"- {insight}")

def render_visualization_page():
    if st.session_state.df is None:
        st.warning("Please upload a dataset first.")
        return
    st.header("Visualize Data")
    df = st.session_state.cleaned_df if st.session_state.cleaned_df is not None else st.session_state.df
    render_bar_chart(df)