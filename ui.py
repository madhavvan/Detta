# === IMPORTS ===
import streamlit as st
import pandas as pd
import dask.dataframe as dd
from openai import OpenAI  # Added this import to resolve NameError
from data_utils import get_cleaning_suggestions, apply_cleaning_operations, get_insights, get_visualization_suggestions, get_dataset_summary
from visualizations import render_chart
import os
import json
from collections import deque
from typing import Union, List, Tuple

# === UPLOAD PAGE ===
def render_upload_page():
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
                if file_size_mb > 50:
                    # Chunked upload for large files
                    chunks = pd.read_csv(uploaded_file, chunksize=10000) if uploaded_file.name.endswith(".csv") else pd.read_excel(uploaded_file, chunksize=10000)
                    df = dd.from_pandas(pd.concat(chunks), npartitions=10)
                    for i in range(100):
                        progress_bar.progress(i + 1, text=f"Processing {(i+1)*file_size_mb/100:.2f}MB ({(i+1)}%)")
                        st.session_state.logs.append(f"Progress: {(i+1)}%")
                    st.session_state.is_dask = True
                else:
                    df = pd.read_csv(uploaded_file) if uploaded_file.name.endswith(".csv") else pd.read_excel(uploaded_file)
                    st.session_state.is_dask = False
                progress_bar.progress(100, text="Upload complete!")
                st.toast("Upload complete!", icon="✅")

                # Validation
                if df.empty or len(df.columns) == 0:
                    st.error("Empty file detected. Upload a valid CSV/Excel.")
                    return
                if df.dtypes.all() == "object":
                    st.warning("No numeric columns. Some features limited.")

                st.session_state.df = df
                st.session_state.cleaned_df = None
                st.session_state.suggestions = []
                st.session_state.cleaning_history = deque(maxlen=5)
                st.session_state.page = 0

                # Immediate Summary
                with st.expander("Dataset Summary", expanded=True):
                    summary = get_dataset_summary(df)
                    st.write(summary)

                # Pagination for Dask
                if st.session_state.is_dask:
                    total_rows = len(df) if isinstance(df, pd.DataFrame) else df.index.size.compute()
                    page_size = 10
                    max_pages = (total_rows - 1) // page_size
                    st.session_state.page = st.number_input("Page", min_value=0, max_value=max_pages, value=0, step=1)
                    start = st.session_state.page * page_size
                    end = start + page_size
                    st.subheader("Dataset Preview")
                    st.dataframe(df[start:end].compute() if st.session_state.is_dask else df[start:end], use_container_width=True, height=300)
                else:
                    st.subheader("Dataset Preview")
                    st.dataframe(df.head(10), use_container_width=True, height=300)
            except Exception as e:
                st.error(f"Error loading file: {str(e)}")
                st.session_state.logs.append(f"Upload error: {str(e)}")
                progress_bar.empty()

# === CLEAN PAGE ===
def render_clean_page(openai_client: OpenAI | None):
    """Render the clean page with validated AI suggestions and multi-level undo."""
    if st.session_state.df is None:
        st.warning("Please upload a dataset on the Upload page.")
        return
    st.header("Clean Dataset")
    df = st.session_state.df

    col1, col2 = st.columns([2, 1])
    with col1:
        st.subheader("Original Preview")
        if st.session_state.is_dask:
            start = st.session_state.page * 10
            st.dataframe(df[start:start+10].compute(), use_container_width=True, height=300)
        else:
            st.dataframe(df.head(10), use_container_width=True, height=300)
    with col2:
        st.subheader("Cleaning Actions")
        with st.expander("Manual Cleaning", expanded=False):
            columns_to_drop = st.multiselect("Drop columns", df.columns if not st.session_state.is_dask else df.columns.compute())
            replace_value = st.text_input("Replace value (e.g., '?')")
            replace_with = st.text_input("With (e.g., 'NaN')")

        if openai_client and st.button("Get AI Suggestions", help="Fetch AI-driven cleaning suggestions"):
            with st.spinner("Generating AI suggestions..."):
                suggestions = get_cleaning_suggestions(df, openai_client)
                st.session_state.suggestions = suggestions
                st.toast("Suggestions generated!", icon="🤖")

        if st.session_state.suggestions:
            with st.expander("AI Suggestions", expanded=True):
                for i, (suggestion, reason, confidence) in enumerate(st.session_state.suggestions):
                    st.checkbox(f"{suggestion} - {reason} (Confidence: {confidence:.2f})", key=f"sugg_{i}")
                    if confidence < 0.5:
                        st.warning(f"Low confidence suggestion: {suggestion}")

    # Apply/Discard Buttons
    col_apply, col_all, col_discard = st.columns(3)
    with col_apply:
        if st.button("Apply Selected", help="Execute selected cleaning steps"):
            selected_suggestions = [sugg for i, sugg in enumerate(st.session_state.suggestions) if st.session_state.get(f"sugg_{i}", False)]
            with st.spinner("Applying cleaning operations..."):
                try:
                    cleaned_df = apply_cleaning_operations(df, selected_suggestions, columns_to_drop, replace_value, replace_with)
                    if not cleaned_df.equals(df):
                        summary = f"Step {len(st.session_state.cleaning_history) + 1}: "
                        if columns_to_drop:
                            summary += f"Dropped {', '.join(columns_to_drop)}, "
                        if replace_value:
                            summary += f"Replaced '{replace_value}' with '{replace_with}', "
                        if selected_suggestions:
                            summary += f"Applied {len(selected_suggestions)} AI suggestions"
                        st.session_state.cleaning_history.append((st.session_state.cleaned_df, summary.strip(", ")))
                        st.session_state.cleaned_df = cleaned_df
                        st.toast(f"Cleaning applied! New shape: {cleaned_df.shape}", icon="✅")
                    else:
                        st.warning("No changes applied. Check inputs or suggestions.")
                except Exception as e:
                    st.error(f"Error applying cleaning: {str(e)}")
    with col_all:
        if st.button("Apply All", help="Execute all AI suggestions"):
            with st.spinner("Applying all suggestions..."):
                try:
                    cleaned_df = apply_cleaning_operations(df, st.session_state.suggestions, columns_to_drop, replace_value, replace_with)
                    if not cleaned_df.equals(df):
                        summary = f"Step {len(st.session_state.cleaning_history) + 1}: Applied all suggestions"
                        st.session_state.cleaning_history.append((st.session_state.cleaned_df, summary))
                        st.session_state.cleaned_df = cleaned_df
                        st.toast(f"Applied {len(st.session_state.suggestions)} suggestions!", icon="✅")
                    else:
                        st.warning("No changes applied.")
                except Exception as e:
                    st.error(f"Error applying all: {str(e)}")
    with col_discard:
        if st.button("Discard All", help="Clear all suggestions"):
            st.session_state.suggestions = []
            st.toast("Suggestions discarded!", icon="🗑️")

    # Undo History
    if st.session_state.cleaning_history:
        with st.expander("Undo History (Last 5 Steps)"):
            history_options = [step[1] for step in st.session_state.cleaning_history]
            selected_step = st.selectbox("Select a step to revert to", history_options)
            if st.button("Revert", help="Undo to selected step"):
                for i, (state, summary) in enumerate(st.session_state.cleaning_history):
                    if summary == selected_step:
                        st.session_state.cleaning_history = deque(list(st.session_state.cleaning_history)[:i+1], maxlen=5)
                        st.session_state.cleaned_df = state if state is not None else df.copy()
                        st.toast(f"Reverted to '{summary}'!", icon="↩️")
                        break

    # Export Cleaning Steps
    if st.session_state.cleaning_history:
        export_data = [{"step": i+1, "summary": summary, "timestamp": datetime.now().isoformat()} for i, (_, summary) in enumerate(st.session_state.cleaning_history)]
        st.download_button("Export Cleaning Steps", data=json.dumps(export_data), file_name=f"cleaning_{datetime.now().strftime('%Y%m%d')}.json", mime="application/json")

    # Cleaned Dataset
    if st.session_state.cleaned_df is not None:
        st.markdown("---")
        st.subheader("Cleaned Dataset")
        view_option = st.radio("View", ["Preview (10 Rows)", "Full Dataset"], horizontal=True, key="view_clean")
        cleaned_df = st.session_state.cleaned_df
        if view_option == "Preview (10 Rows)":
            st.dataframe(cleaned_df.head(10).compute() if st.session_state.is_dask else cleaned_df.head(10), use_container_width=True, height=300)
        else:
            st.dataframe(cleaned_df.compute() if st.session_state.is_dask else cleaned_df, use_container_width=True, height=600)

def render_insights_page(openai_client: OpenAI | None):
    if st.session_state.df is None:
        st.warning("Please upload a dataset first.")
        return
    st.header("Insights")
    df = st.session_state.cleaned_df if st.session_state.cleaned_df is not None else st.session_state.df
    if st.session_state.is_dask:
        start = st.session_state.page * 10
        st.dataframe(df[start:start+10].compute(), use_container_width=True, height=300)
    else:
        st.dataframe(df.head(10), use_container_width=True, height=300)

    if openai_client and st.button("Generate Insights", help="Get AI-driven insights"):
        with st.spinner("Analyzing dataset..."):
            insights = get_insights(df, openai_client)
            st.subheader("Key Insights")
            for i, insight in enumerate(insights):
                if st.button(f"{insight}", key=f"insight_{i}"):
                    st.session_state.chat_history.append({"user": f"Visualize: {insight}", "assistant": "Generating visualization..."})
                    st.session_state.selected_insight = insight
            st.toast("Insights generated!", icon="📊")

def render_visualization_page(openai_client: OpenAI | None):
    if st.session_state.df is None:
        st.warning("Please upload a dataset first.")
        return
    st.header("Visualize Data")
    df = st.session_state.cleaned_df if st.session_state.cleaned_df is not None else st.session_state.df

    if openai_client and st.button("Suggest Visualizations", help="Get AI visualization suggestions"):
        with st.spinner("Generating visualization suggestions..."):
            suggestions = get_visualization_suggestions(df, openai_client)
            st.session_state.vis_suggestions = suggestions
            st.toast("Visualization suggestions ready!", icon="📈")

    if "vis_suggestions" in st.session_state and st.session_state.vis_suggestions:
        st.subheader("AI Visualization Suggestions")
        selected_vis = st.selectbox("Choose a suggestion", [s["description"] for s in st.session_state.vis_suggestions])
        if selected_vis:
            vis_config = next(s for s in st.session_state.vis_suggestions if s["description"] == selected_vis)
            render_chart(df, vis_config["chart_type"], vis_config["x"], vis_config["y"])
    else:
        render_chart(df)