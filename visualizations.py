import streamlit as st
import plotly.express as px

def render_bar_chart(df):
    st.subheader("Bar Chart")
    col1, col2 = st.columns(2)
    with col1:
        x_col = st.selectbox("X-axis", df.columns)
    with col2:
        y_col = st.selectbox("Y-axis", df.select_dtypes(include=["int64", "float64"]).columns)
    fig = px.bar(df, x=x_col, y=y_col, title=f"{y_col} by {x_col}", template="plotly_white")
    fig.update_layout(margin=dict(l=20, r=20, t=40, b=20))
    st.plotly_chart(fig, use_container_width=True)