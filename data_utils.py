import pandas as pd
from openai import OpenAI
import os
import streamlit as st
import httpx

def initialize_openai_client():
    api_key = st.secrets.get("OPENAI_API_KEY") or os.getenv("OPENAI_API_KEY")
    if not api_key:
        return None
    return OpenAI(api_key=api_key, http_client=httpx.Client())

@st.cache_data
def analyze_dataset(df, client):
    if client is None:
        return [("AI unavailable: No API key.", False)]
    
    # Dataset summary
    summary = f"Shape: {df.shape}\nColumns: {list(df.columns)}\n"
    for col in df.columns:
        missing = df[col].isna().sum()
        dtype = str(df[col].dtype)
        unique = df[col].nunique()
        sample = df[col].head(5).tolist()
        summary += f"{col}: {dtype}, {missing} missing, {unique} unique, sample: {sample}\n"
    
    # AI prompt
    prompt = f"""
    Analyze this dataset summary and provide specific, actionable suggestions for enhancement that can be directly applied via code:
    {summary}
    Suggestions must be precise (e.g., "Impute missing values in [col] with mean"), avoiding vague advice. For each suggestion, indicate if it's actionable (can be coded) or informational (general insight). Format as:
    - [Actionable] Suggestion
    - [Informational] Suggestion
    """
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": prompt}],
        max_tokens=1000
    )
    
    # Parse suggestions
    suggestions = []
    for line in response.choices[0].message.content.split("\n"):
        if line.startswith("- [Actionable]"):
            suggestions.append((line.replace("- [Actionable] ", ""), True))
        elif line.startswith("- [Informational]"):
            suggestions.append((line.replace("- [Informational] ", ""), False))
    return suggestions

def apply_selected_operations(df, selected_suggestions):
    cleaned_df = df.copy()
    
    for suggestion, _ in selected_suggestions:
        try:
            if "Impute missing values in" in suggestion:
                col = suggestion.split("in ")[1].split(" with")[0].strip()
                method = suggestion.split("with ")[1].strip()
                if col in cleaned_df.columns:
                    if method == "mean":
                        cleaned_df[col] = cleaned_df[col].fillna(cleaned_df[col].mean())
                    elif method == "median":
                        cleaned_df[col] = cleaned_df[col].fillna(cleaned_df[col].median())
                    elif method == "mode":
                        cleaned_df[col] = cleaned_df[col].fillna(cleaned_df[col].mode()[0])
            elif "Drop rows with missing values" in suggestion:
                cleaned_df = cleaned_df.dropna()
            elif "Remove duplicate rows" in suggestion:
                cleaned_df = cleaned_df.drop_duplicates()
            elif "Label encode" in suggestion:
                col = suggestion.split("column ")[1].strip()
                if col in cleaned_df.columns:
                    cleaned_df[col] = pd.factorize(cleaned_df[col])[0]
            elif "One-hot encode" in suggestion:
                col = suggestion.split("column ")[1].strip()
                if col in cleaned_df.columns:
                    cleaned_df = pd.get_dummies(cleaned_df, columns=[col], prefix=col)
            elif "Normalize" in suggestion:
                col = suggestion.split("column ")[1].strip()
                if col in cleaned_df.columns and pd.api.types.is_numeric_dtype(cleaned_df[col]):
                    cleaned_df[col] = (cleaned_df[col] - cleaned_df[col].min()) / (cleaned_df[col].max() - cleaned_df[col].min())
            elif "Standardize" in suggestion:
                col = suggestion.split("column ")[1].strip()
                if col in cleaned_df.columns and pd.api.types.is_numeric_dtype(cleaned_df[col]):
                    cleaned_df[col] = (cleaned_df[col] - cleaned_df[col].mean()) / cleaned_df[col].std()
            elif "Convert" in suggestion and "to datetime" in suggestion:
                col = suggestion.split("column ")[1].split(" to")[0].strip()
                if col in cleaned_df.columns:
                    cleaned_df[col] = pd.to_datetime(cleaned_df[col], errors='coerce')
            elif "Remove invalid values in" in suggestion:
                col = suggestion.split("in ")[1].strip()
                if col in cleaned_df.columns:
                    cleaned_df[col] = pd.to_numeric(cleaned_df[col], errors='coerce').fillna(pd.NA)
            elif "Optimize data type for" in suggestion:
                col = suggestion.split("for ")[1].strip()
                if col in cleaned_df.columns:
                    if pd.api.types.is_integer_dtype(cleaned_df[col]):
                        cleaned_df[col] = pd.to_numeric(cleaned_df[col], downcast='integer')
                    elif pd.api.types.is_float_dtype(cleaned_df[col]):
                        cleaned_df[col] = pd.to_numeric(cleaned_df[col], downcast='float')
        except Exception as e:
            st.warning(f"Failed to apply: {suggestion} - {str(e)}")
    
    return cleaned_df