# === IMPORTS ===
import pandas as pd
import dask.dataframe as dd
from openai import OpenAI
import os
import streamlit as st
import httpx
from scipy.stats import skew
from concurrent.futures import ThreadPoolExecutor
import logging
from typing import List, Tuple, Union, Dict, Any

# === AI CLIENT ===
def initialize_openai_client() -> OpenAI | None:
    """Initialize OpenAI client with API key."""
    api_key = st.secrets.get("OPENAI_API_KEY") or os.getenv("OPENAI_API_KEY")
    if not api_key:
        logging.warning("No OpenAI API key provided.")
        return None
    try:
        return OpenAI(api_key=api_key, http_client=httpx.Client())
    except Exception as e:
        logging.error(f"OpenAI client initialization failed: {str(e)}")
        return None

# === DATASET SUMMARY ===
@st.cache_data
def get_dataset_summary(df: Union[pd.DataFrame, dd.DataFrame]) -> str:
    """Generate a summary of the dataset."""
    if isinstance(df, dd.DataFrame):
        df = df.compute()
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

# === AI SUGGESTIONS ===
def get_cleaning_suggestions(df: Union[pd.DataFrame, dd.DataFrame], client: OpenAI | None) -> List[Tuple[str, str, float]]:
    """Fetch and validate cleaning suggestions from GPT-4o."""
    if client is None:
        return [("AI unavailable", "No OpenAI API key provided", 0.0)]
    
    summary = get_dataset_summary(df)
    prompt = (
        f"Given this dataset summary:\n{summary}\n"
        "Provide specific, actionable data cleaning suggestions in these formats only:\n"
        "- 'Fill missing values in [column_name] with [mean/median]'\n"
        "- 'Drop column [column_name]'\n"
        "- 'Replace [value] with [new_value]'\n"
        "Include a reason after each suggestion with ' - Reason: [explanation]'."
    )
    
    with ThreadPoolExecutor(max_workers=5) as executor:
        future = executor.submit(client.chat.completions.create, model="gpt-4o", messages=[{"role": "user", "content": prompt}], max_tokens=500)
        try:
            response = future.result(timeout=10)
            suggestions_text = response.choices[0].message.content.strip()
            logging.info(f"Raw AI response: {suggestions_text}")
        except Exception as e:
            logging.error(f"Error in GPT-4o call: {str(e)}")
            return [("Error generating suggestions", str(e), 0.0)]

    suggestions = []
    df_cols = df.columns if isinstance(df, pd.DataFrame) else df.columns.compute()
    for line in suggestions_text.split("\n"):
        line = line.strip()
        if line and ("Fill missing values in" in line or "Drop column" in line or "Replace" in line):
            parts = line.split(" - Reason: ") if " - Reason: " in line else [line, "No reason provided"]
            suggestion = parts[0].strip("- ").strip()
            reason = parts[1] if len(parts) > 1 else "No reason provided"
            confidence = 0.9  # Default high confidence
            
            # Validation
            if "Fill missing values in" in suggestion:
                col = suggestion.split("in ")[1].split(" with")[0].strip()
                method = suggestion.split("with ")[1].strip().lower()
                if col not in df_cols:
                    confidence = 0.2
                    reason += " (Column not found)"
                elif df[col].dtype not in ["int64", "float64"]:
                    confidence = 0.3
                    reason += " (Column not numeric)"
            elif "Drop column" in suggestion:
                col = suggestion.split("Drop column ")[1].strip()
                if col not in df_cols:
                    confidence = 0.2
                    reason += " (Column not found)"
            elif "Replace" in suggestion:
                value = suggestion.split(" ")[1].strip("'")
                if not df.isin([value]).any().any():
                    confidence = 0.4
                    reason += " (Value not found in dataset)"
            
            suggestions.append((suggestion, reason, confidence))
    
    return suggestions if suggestions else [("No valid suggestions generated", "AI response was empty or malformed", 0.0)]

# === CLEANING OPERATIONS ===
def apply_cleaning_operations(df: Union[pd.DataFrame, dd.DataFrame], selected_suggestions: List[Tuple[str, str, float]], 
                              columns_to_drop: List[str], replace_value: str, replace_with: str) -> Union[pd.DataFrame, dd.DataFrame]:
    """Apply manual and AI-driven cleaning operations."""
    cleaned_df = df.copy()
    is_dask = isinstance(df, dd.DataFrame)

    # Manual operations
    if columns_to_drop:
        cleaned_df = cleaned_df.drop(columns=columns_to_drop)
        logging.info(f"Dropped columns: {columns_to_drop}")
    if replace_value and replace_with:
        new_value = pd.NA if replace_with.lower() == "nan" else replace_with
        cleaned_df = cleaned_df.replace(replace_value, new_value)
        logging.info(f"Replaced '{replace_value}' with '{new_value}'")

    # AI suggestions
    for suggestion, reason, confidence in selected_suggestions:
        try:
            if "Fill missing values in" in suggestion:
                col = suggestion.split("in ")[1].split(" with")[0].strip()
                method = suggestion.split("with ")[1].strip().lower()
                if col in cleaned_df.columns:
                    if method == "mean":
                        cleaned_df[col] = cleaned_df[col].fillna(cleaned_df[col].mean() if not is_dask else cleaned_df[col].mean().compute())
                    elif method == "median":
                        cleaned_df[col] = cleaned_df[col].fillna(cleaned_df[col].median() if not is_dask else cleaned_df[col].median().compute())
                    logging.info(f"Filled missing in '{col}' with {method}, confidence: {confidence}")
            elif "Drop column" in suggestion:
                col = suggestion.split("Drop column ")[1].strip()
                if col in cleaned_df.columns:
                    cleaned_df = cleaned_df.drop(columns=[col])
                    logging.info(f"Dropped column '{col}', confidence: {confidence}")
            elif "Replace" in suggestion:
                parts = suggestion.split(" ")
                value = parts[1].strip("'")
                new_value = parts[3].strip("'")
                new_value = pd.NA if new_value.lower() == "nan" else new_value
                cleaned_df = cleaned_df.replace(value, new_value)
                logging.info(f"Replaced '{value}' with '{new_value}', confidence: {confidence}")
        except Exception as e:
            logging.error(f"Error applying suggestion '{suggestion}': {str(e)}")
    
    return cleaned_df

# === INSIGHTS ===
@st.cache_data
def get_insights(df: Union[pd.DataFrame, dd.DataFrame], client: OpenAI | None) -> List[str]:
    """Generate dataset insights."""
    if client is None:
        return ["AI unavailable: No OpenAI API key provided"]
    summary = get_dataset_summary(df)
    prompt = f"Analyze this dataset summary:\n{summary}\nProvide key insights with statistical reasoning."
    with ThreadPoolExecutor(max_workers=5) as executor:
        future = executor.submit(client.chat.completions.create, model="gpt-4o", messages=[{"role": "user", "content": prompt}], max_tokens=300)
        try:
            response = future.result(timeout=10)
            return response.choices[0].message.content.strip().split("\n")
        except Exception as e:
            logging.error(f"Error in get_insights: {str(e)}")
            return ["Error generating insights"]

# === VISUALIZATION SUGGESTIONS ===
@st.cache_data
def get_visualization_suggestions(df: Union[pd.DataFrame, dd.DataFrame], client: OpenAI | None) -> List[Dict[str, Any]]:
    """Suggest visualizations."""
    if client is None:
        return []
    summary = get_dataset_summary(df)
    prompt = f"Given this dataset summary:\n{summary}\nSuggest 3 visualizations (chart type, X-axis, Y-axis) with reasons."
    with ThreadPoolExecutor(max_workers=5) as executor:
        future = executor.submit(client.chat.completions.create, model="gpt-4o", messages=[{"role": "user", "content": prompt}], max_tokens=200)
        try:
            response = future.result(timeout=10)
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
            logging.error(f"Error in get_visualization_suggestions: {str(e)}")
            return []

# === CHAT ===
def chat_with_gpt(df: Union[pd.DataFrame, dd.DataFrame], message: str, client: OpenAI | None) -> str:
    """Handle chat queries."""
    if client is None:
        return "AI unavailable: No OpenAI API key provided"
    summary = get_dataset_summary(df)
    if "correlation" in message.lower():
        numeric_cols = df.select_dtypes(include=["int64", "float64"]).columns
        if len(numeric_cols) >= 2:
            corr = df[numeric_cols[0]].corr(df[numeric_cols[1]]) if not isinstance(df, dd.DataFrame) else df[numeric_cols[0]].corr(df[numeric_cols[1]]).compute()
            return f"The correlation between {numeric_cols[0]} and {numeric_cols[1]} is {corr:.2f}."
    if "who are you" in message.lower():
        return "I'm your assistant, built for data analysis."
    prompt = f"Dataset summary:\n{summary}\nQuestion: {message}"
    with ThreadPoolExecutor(max_workers=5) as executor:
        future = executor.submit(client.chat.completions.create, model="gpt-4o", messages=[{"role": "user", "content": prompt}], max_tokens=200)
        try:
            response = future.result(timeout=10)
            return response.choices[0].message.content.strip()
        except Exception as e:
            logging.error(f"Error in chat_with_gpt: {str(e)}")
            return "Error processing your request"

def get_auto_suggestions(df: Union[pd.DataFrame, dd.DataFrame]) -> List[str]:
    """Provide chat auto-suggestions."""
    return [
        "What’s the correlation between the first two numeric columns?",
        "Which column has the most missing values?",
        "Suggest a cleaning step for the dataset."
    ]