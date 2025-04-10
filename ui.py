import streamlit as st
import pandas as pd
from data_utils import get_cleaning_suggestions, apply_cleaning_operations, get_insights, get_visualization_suggestions
from visualizations import render_chart
import os

def render_upload_page():
    st.header("Upload Dataset")
    col1, col2 = st.columns([3, 1])
    with col1:
        uploaded_file = st.file_uploader("Upload CSV or Excel (max 200MB)", type=["csv", "xlsx"], help="Supports CSV and Excel files.")
    with col2:
        st.write("")  # Spacer
        st.write("File size limit: 200MB")

    if uploaded_file:
        # File size validation
        file_size_mb = os.path.getsize(uploaded_file.name) / (1024 * 1024) if os.path.exists(uploaded_file.name) else uploaded_file.size / (1024 * 1024)
        if file_size_mb > 200:
            st.error("File exceeds 200MB limit. Please upload a smaller file.")
            return

        with st.spinner("Loading dataset..."):
            try:
                if uploaded_file.name.endswith(".csv"):
                    if file_size_mb > 50:  # Chunked processing for large files
                        chunks = pd.read_csv(uploaded_file, chunksize=10000)
                        df = pd.concat([chunk for chunk in chunks], ignore_index=True)
                    else:
                        df = pd.read_csv(uploaded_file)
                else:
                    df = pd.read_excel(uploaded_file)
                st.session_state.df = df
                st.session_state.cleaned_df = None
                st.session_state.suggestions = []
                st.session_state.cleaning_history = []  # Initialize action history
                st.toast(f"Loaded {uploaded_file.name} successfully!", icon="✅")
                st.subheader("Dataset Preview")
                st.dataframe(df.head(10), use_container_width=True, height=300)
            except Exception as e:
                st.error(f"Error loading file: {str(e)}")
                st.session_state.logs.append(f"Upload error: {str(e)}")

def render_clean_page(openai_client):
    if st.session_state.df is None:
        st.warning("Please upload a dataset on the Upload page.")
        return
    st.header("Clean Dataset")
    df = st.session_state.df

    # Two-column layout
    col1, col2 = st.columns([2, 1])
    with col1:
        st.subheader("Original Preview")
        st.dataframe(df.head(10), use_container_width=True, height=300)
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
                st.toast("Suggestions generated!", icon="🤖")

        if st.session_state.suggestions:
            with st.expander("AI Suggestions", expanded=True):
                for i, (suggestion, reason) in enumerate(st.session_state.suggestions):
                    st.checkbox(f"{suggestion} ({reason})", key=f"sugg_{i}")

    # Apply and Undo buttons
    col_apply, col_undo = st.columns(2)
    with col_apply:
        if st.button("Apply Cleaning", use_container_width=True):
            selected_suggestions = [sugg for i, sugg in enumerate(st.session_state.suggestions) if st.session_state.get(f"sugg_{i}", False)]
            with st.spinner("Applying cleaning operations..."):
                cleaned_df = apply_cleaning_operations(df, selected_suggestions, columns_to_drop, replace_value, replace_with)
                st.session_state.cleaning_history.append((st.session_state.cleaned_df, selected_suggestions, columns_to_drop, replace_value, replace_with))
                st.session_state.cleaned_df = cleaned_df
                st.toast(f"Cleaning applied! New shape: {cleaned_df.shape}", icon="✅")
    with col_undo:
        if st.button("Undo Last Action", use_container_width=True, disabled=len(st.session_state.cleaning_history) == 0):
            last_state, *_ = st.session_state.cleaning_history.pop()
            st.session_state.cleaned_df = last_state if last_state is not None else df.copy()
            st.toast("Last cleaning action undone!", icon="↩️")

    # Cleaned dataset display with sorting/filtering
    if st.session_state.cleaned_df is not None:
        st.markdown("---")
        st.subheader("Cleaned Dataset")
        view_option = st.radio("View", ["Preview (10 Rows)", "Full Dataset"], horizontal=True, key="view_clean")
        with st.container():
            cleaned_df = st.session_state.cleaned_df
            if view_option == "Preview (10 Rows)":
                st.dataframe(cleaned_df.head(10), use_container_width=True, height=300)
            else:
                st.dataframe(cleaned_df, use_container_width=True, height=600)

def render_insights_page(openai_client):
    if st.session_state.df is None:
        st.warning("Please upload a dataset first.")
        return
    st.header("Insights")
    df = st.session_state.cleaned_df if st.session_state.cleaned_df is not None else st.session_state.df
    st.dataframe(df.head(10), use_container_width=True, height=300)

    if openai_client and st.button("Generate Insights"):
        with st.spinner("Analyzing dataset..."):
            insights = get_insights(df, openai_client)
            st.subheader("Key Insights")
            for i, insight in enumerate(insights):
                if st.button(f"{insight}", key=f"insight_{i}"):  # Clickable insights
                    st.session_state.chat_history.append({"user": f"Visualize: {insight}", "assistant": "Generating visualization..."})
                    st.session_state.selected_insight = insight
            st.toast("Insights generated!", icon="📊")

def render_visualization_page(openai_client):
    if st.session_state.df is None:
        st.warning("Please upload a dataset first.")
        return
    st.header("Visualize Data")
    df = st.session_state.cleaned_df if st.session_state.cleaned_df is not None else st.session_state.df

    if openai_client and st.button("Suggest Visualizations"):
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