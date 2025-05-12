# ui.py
"""
Contains functions to render non-authentication UI pages for the Detta application.
"""
import streamlit as st
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
from collections import deque
from signin import set_page  # Import set_page from signin.py

# --- Non-Authentication UI Functions ---
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
