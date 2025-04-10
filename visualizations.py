import streamlit as st
import plotly.express as px

def render_chart(df, chart_type=None, x_col=None, y_col=None):
    st.subheader("Data Visualization")
    chart_options = ["Bar", "Scatter", "Histogram", "Box"]
    col1, col2, col3 = st.columns(3)
    
    with col1:
        chart_type = st.selectbox("Chart Type", chart_options, index=chart_options.index(chart_type) if chart_type else 0)
    with col2:
        x_col = st.selectbox("X-axis", df.columns, index=df.columns.get_loc(x_col) if x_col in df.columns else 0)
    with col3:
        numeric_cols = df.select_dtypes(include=["int64", "float64"]).columns
        y_col = st.selectbox("Y-axis", numeric_cols, index=numeric_cols.get_loc(y_col) if y_col in numeric_cols else 0)

    try:
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
    except Exception as e:
        st.error(f"Error rendering chart: {str(e)}")
        st.session_state.logs.append(f"Visualization error: {str(e)}")