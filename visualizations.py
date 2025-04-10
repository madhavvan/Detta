# === IMPORTS ===
import streamlit as st
import plotly.express as px
import tempfile
from typing import Union
import pandas as pd
import dask.dataframe as dd

def render_chart(df: Union[pd.DataFrame, dd.DataFrame], chart_type: str = None, x_col: str = None, y_col: str = None):
    """Render interactive charts with export option."""
    st.subheader("Data Visualization")
    chart_options = ["Bar", "Scatter", "Histogram", "Box"]
    col1, col2, col3 = st.columns(3)
    
    with col1:
        chart_type = st.selectbox("Chart Type", chart_options, index=chart_options.index(chart_type) if chart_type else 0)
    with col2:
        cols = df.columns if isinstance(df, pd.DataFrame) else df.columns.compute()
        x_col = st.selectbox("X-axis", cols, index=cols.get_loc(x_col) if x_col in cols else 0)
    with col3:
        numeric_cols = df.select_dtypes(include=["int64", "float64"]).columns if isinstance(df, pd.DataFrame) else df.select_dtypes(include=["int64", "float64"]).columns.compute()
        y_col = st.selectbox("Y-axis", numeric_cols, index=numeric_cols.get_loc(y_col) if y_col in numeric_cols else 0)

    try:
        if isinstance(df, dd.DataFrame):
            df = df.compute()
        if chart_type == "Bar":
            fig = px.bar(df, x=x_col, y=y_col, title=f"{y_col} by {x_col}", template="plotly_white")
        elif chart_type == "Scatter":
            fig = px.scatter(df, x=x_col, y=y_col, title=f"{y_col} vs {x_col}", template="plotly_white", trendline="ols")
        elif chart_type == "Histogram":
            fig = px.histogram(df, x=x_col, title=f"Distribution of {x_col}", template="plotly_white")
        elif chart_type == "Box":
            fig = px.box(df, x=x_col, y=y_col, title=f"{y_col} by {x_col}", template="plotly_white")
        
        fig.update_layout(margin=dict(l=20, r=20, t=40, b=20))
        st.plotly_chart(fig, use_container_width=True)

        # Export as PNG
        with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as tmp:
            fig.write_image(tmp.name, format="png")
            with open(tmp.name, "rb") as f:
                st.download_button("Export as PNG", f, file_name=f"chart_{x_col}_{y_col}.png", mime="image/png")
        os.unlink(tmp.name)
    except Exception as e:
        st.error(f"Error rendering chart: {str(e)}")
        st.session_state.logs.append(f"Visualization error: {str(e)}")