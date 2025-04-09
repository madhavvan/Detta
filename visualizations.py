import streamlit as st
import plotly.express as px

def render_bar_chart(df):
    st.subheader("Bar Chart")
    x_col = st.selectbox("Select X-axis column", df.columns)
    y_col = st.selectbox("Select Y-axis column", df.select_dtypes(include=["int64", "float64"]).columns)
    fig = px.bar(df, x=x_col, y=y_col, title=f"Bar Chart: {y_col} by {x_col}")
    st.plotly_chart(fig)