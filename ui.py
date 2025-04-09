import streamlit as st
import pandas as pd
from data_utils import get_cleaning_suggestions, apply_cleaning_operations, get_insights
from visualizations import render_bar_chart

def render_upload_page():
    st.header("Upload Your Dataset")
    uploaded_file = st.file_uploader("Drag and drop file here (CSV or Excel)", type=["csv", "xlsx"])
    if uploaded_file:
        try:
            if uploaded_file.name.endswith(".csv"):
                df = pd.read_csv(uploaded_file)
            else:
                df = pd.read_excel(uploaded_file)
            st.session_state.df = df
            st.session_state.cleaned_df = None
            st.session_state.suggestions = []
            st.success("File uploaded successfully!")
            st.subheader("Original Data Preview")
            st.dataframe(df.head(10))
        except Exception as e:
            st.error(f"Error loading file: {str(e)}")

def render_clean_page(openai_client):
    if st.session_state.df is None:
        st.warning("Please upload a dataset first.")
        return
    st.header("Clean Your Dataset")
    df = st.session_state.df
    st.subheader("Preview (First 10 Rows)")
    st.dataframe(df.head(10))
    
    # AI cleaning suggestions
    if openai_client and st.button("Generate AI Cleaning Suggestions"):
        with st.spinner("Generating suggestions..."):
            suggestions = get_cleaning_suggestions(df, openai_client)
            st.session_state.suggestions = suggestions
            st.subheader("AI Cleaning Suggestions")
            for i, (suggestion, reason) in enumerate(suggestions):
                st.checkbox(f"{suggestion} - Reason: {reason}", key=f"suggestion_{i}")

    # Apply selected suggestions and manual cleaning
    columns_to_drop = st.multiselect("Select columns to drop", df.columns)
    replace_value = st.text_input("Value to replace (e.g., '?')")
    replace_with = st.text_input("Replace with (e.g., 'NaN')")
    
    if st.button("Apply Cleaning"):
        selected_suggestions = [sugg for i, sugg in enumerate(st.session_state.suggestions) if st.session_state.get(f"suggestion_{i}", False)]
        cleaned_df = apply_cleaning_operations(df, selected_suggestions, columns_to_drop, replace_value, replace_with)
        st.session_state.cleaned_df = cleaned_df
        st.success("Cleaning steps applied successfully!")
        
        # Display options for cleaned data
        st.subheader("Cleaned Data")
        view_option = st.radio("View Options", ["Preview (First 10 Rows)", "Full Dataset"])
        if view_option == "Preview (First 10 Rows)":
            st.dataframe(cleaned_df.head(10))
        else:
            st.dataframe(cleaned_df)

def render_insights_page(openai_client):
    if st.session_state.df is None:
        st.warning("Please upload a dataset first.")
        return
    st.header("Insights")
    df = st.session_state.cleaned_df if st.session_state.cleaned_df is not None else st.session_state.df
    if openai_client and st.button("Generate Insights"):
        with st.spinner("Generating insights..."):
            insights = get_insights(df, openai_client)
            for insight in insights:
                st.write(f"- {insight}")

def render_visualization_page():
    if st.session_state.df is None:
        st.warning("Please upload a dataset first.")
        return
    st.header("Visualize Your Data")
    df = st.session_state.cleaned_df if st.session_state.cleaned_df is not None else st.session_state.df
    render_bar_chart(df)