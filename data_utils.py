import pandas as pd
from openai import OpenAI
import os
import streamlit as st
import httpx
from scipy.stats import skew

def initialize_openai_client():
    api_key = st.secrets.get("OPENAI_API_KEY") or os.getenv("OPENAI_API_KEY")
    if not api_key:
        st.session_state.logs.append("No OpenAI API key provided.")
        return None
    try:
        client = OpenAI(api_key=api_key, http_client=httpx.Client())
        return client
    except Exception as e:
        st.session_state.logs.append(f"OpenAI client initialization failed: {str(e)}")
        return None

@st.cache_data
def get_dataset_summary(df):
    summary = f"Dataset shape: {df.shape}\nColumns: {list(df.columns)}\n"
    for col in df.columns:
        missing = df[col].isna().sum()
        dtype = str(df[col].dtype)
        unique = df[col].nunique()
        if df[col].dtype in ["int64", "float64"]:
            sk = skew(df[col].dropna())
            summary += f"{col}: {dtype}, {missing} missing, {unique} unique, skew={sk:.2f}\n"
        else:
            summary += f"{col}: {dtype}, {missing} missing, {unique} unique\n"
    return summary

def get_cleaning_suggestions(df, client):
    if client is None:
        return [("AI unavailable", "No OpenAI API key provided")]
    
    summary = get_dataset_summary(df)
    prompt = (
        f"Given this dataset summary:\n{summary}\n"
        "Provide specific, actionable data cleaning suggestions in the following formats only:\n"
        "- 'Fill missing values in [column_name] with [mean/median]'\n"
        "- 'Drop column [column_name]'\n"
        "- 'Replace [value] with [new_value]'\n"
        "Include a reason after each suggestion with ' - Reason: [explanation]'. "
        "List at least 3 suggestions if applicable."
    )
    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=500
        )
        suggestions_text = response.choices[0].message.content.strip()
        st.session_state.logs.append(f"Raw AI response: {suggestions_text}")  # Log raw response for debugging
        
        suggestions = []
        for line in suggestions_text.split("\n"):
            line = line.strip()
            if line and ("Fill missing values in" in line or "Drop column" in line or "Replace" in line):
                parts = line.split(" - Reason: ") if " - Reason: " in line else [line, "No reason provided"]
                suggestion = parts[0].strip("- ").strip()
                reason = parts[1] if len(parts) > 1 else "No reason provided"
                # Validate suggestion format
                if (
                    "Fill missing values in" in suggestion and "with" in suggestion or
                    "Drop column" in suggestion or
                    "Replace" in suggestion and "with" in suggestion
                ):
                    suggestions.append((suggestion, reason))
        return suggestions if suggestions else [("No valid suggestions generated", "AI response was empty or malformed")]
    except Exception as e:
        st.session_state.logs.append(f"Error in get_cleaning_suggestions: {str(e)}")
        return [("Error generating suggestions", str(e))]

def apply_cleaning_operations(df, selected_suggestions, columns_to_drop, replace_value, replace_with):
    cleaned_df = df.copy()
    
    # Manual column dropping
    if columns_to_drop:
        cleaned_df = cleaned_df.drop(columns=columns_to_drop)
        st.session_state.logs.append(f"Dropped columns: {columns_to_drop}")

    # Manual value replacement
    if replace_value and replace_with:
        try:
            new_value = pd.NA if replace_with.lower() == "nan" else replace_with
            cleaned_df = cleaned_df.replace(replace_value, new_value)
            st.session_state.logs.append(f"Replaced '{replace_value}' with '{new_value}'")
        except Exception as e:
            st.session_state.logs.append(f"Error in manual replacement: {str(e)}")

    # Apply AI suggestions
    for suggestion, _ in selected_suggestions:
        try:
            if "Fill missing values in" in suggestion:
                col = suggestion.split("in ")[1].split(" with")[0].strip()
                method = suggestion.split("with ")[1].strip().lower()
                if col in cleaned_df.columns:
                    if method == "mean":
                        cleaned_df[col] = cleaned_df[col].fillna(cleaned_df[col].mean())
                    elif method == "median":
                        cleaned_df[col] = cleaned_df[col].fillna(cleaned_df[col].median())
                    st.session_state.logs.append(f"Filled missing in '{col}' with {method}")
                else:
                    st.session_state.logs.append(f"Column '{col}' not found in dataset")
            elif "Drop column" in suggestion:
                col = suggestion.split("Drop column ")[1].strip()
                if col in cleaned_df.columns:
                    cleaned_df = cleaned_df.drop(columns=[col])
                    st.session_state.logs.append(f"Dropped column '{col}'")
                else:
                    st.session_state.logs.append(f"Column '{col}' not found in dataset")
            elif "Replace" in suggestion and "with" in suggestion:
                parts = suggestion.split(" ")
                value = parts[1].strip("'")
                new_value = parts[3].strip("'")
                new_value = pd.NA if new_value.lower() == "nan" else new_value
                cleaned_df = cleaned_df.replace(value, new_value)
                st.session_state.logs.append(f"Replaced '{value}' with '{new_value}'")
        except Exception as e:
            st.session_state.logs.append(f"Error applying suggestion '{suggestion}': {str(e)}")
    
    return cleaned_df

@st.cache_data
def get_insights(df, client):
    if client is None:
        return ["AI unavailable: No OpenAI API key provided"]
    
    summary = get_dataset_summary(df)
    prompt = f"Analyze this dataset summary:\n{summary}\nProvide key insights with statistical reasoning."
    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=300
        )
        return response.choices[0].message.content.strip().split("\n")
    except Exception as e:
        st.session_state.logs.append(f"Error in get_insights: {str(e)}")
        return ["Error generating insights"]

@st.cache_data
def get_visualization_suggestions(df, client):
    if client is None:
        return []
    
    summary = get_dataset_summary(df)
    prompt = f"Given this dataset summary:\n{summary}\nSuggest 3 visualizations (chart type, X-axis, Y-axis) with reasons."
    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=200
        )
        suggestions_text = response.choices[0].message.content.strip()
        suggestions = []
        for line in suggestions_text.split("\n"):
            if "Chart:" in line:
                parts = line.split(" - ")
                desc = parts[0].strip()
                reason = parts[1].strip() if len(parts) > 1 else "No reason provided"
                chart_type = desc.split("Chart:")[1].split(",")[0].strip()
                x = desc.split("X:")[1].split(",")[0].strip()
                y = desc.split("Y:")[1].strip()
                suggestions.append({"description": desc, "chart_type": chart_type, "x": x, "y": y, "reason": reason})
        return suggestions
    except Exception as e:
        st.session_state.logs.append(f"Error in get_visualization_suggestions: {str(e)}")
        return []

def chat_with_gpt(df, message, client):
    if client is None:
        return "AI unavailable: No OpenAI API key provided"
    
    summary = get_dataset_summary(df)
    if "correlation" in message.lower():
        numeric_cols = df.select_dtypes(include=["int64", "float64"]).columns
        if len(numeric_cols) >= 2:
            corr = df[numeric_cols[0]].corr(df[numeric_cols[1]])
            return f"The correlation between {numeric_cols[0]} and {numeric_cols[1]} is {corr:.2f}."
    if "who are you" in message.lower():
        return "I'm your assistant, built for data analysis."
    
    prompt = f"Dataset summary:\n{summary}\nQuestion: {message}"
    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=200
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        st.session_state.logs.append(f"Error in chat_with_gpt: {str(e)}")
        return "Error processing your request"

def get_auto_suggestions(df):
    return [
        "What’s the correlation between the first two numeric columns?",
        "Which column has the most missing values?",
        "Suggest a cleaning step for the dataset."
    ]