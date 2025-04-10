import pandas as pd
import numpy as np
import openai
from openai import OpenAI
import streamlit as st
import re
import logging
from logging.handlers import RotatingFileHandler
import os
import httpx
from typing import Dict, List, Tuple, Optional, Union

# Set up logging with rotation
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = RotatingFileHandler('data_utils.log', maxBytes=5*1024*1024, backupCount=3)
    handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
    logger.addHandler(handler)

def initialize_openai_client() -> Optional[OpenAI]:
    """Initialize OpenAI client with API key."""
    api_key = None
    try:
        api_key = st.secrets.get("OPENAI_API_KEY") or os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("OpenAI API key not found.")
        logger.info("Successfully loaded OPENAI_API_KEY")
        return OpenAI(api_key=api_key, http_client=httpx.Client())
    except Exception as e:
        logger.error(f"Failed to load OpenAI API key: {str(e)}")
        st.error("OpenAI API key missing. Configure it in secrets.toml or environment variables.")
        return None

# Initialize OpenAI client globally
client = initialize_openai_client()
AI_AVAILABLE = client is not None

def analyze_dataset(df: pd.DataFrame) -> Dict[str, Union[int, List[str], bool]]:
    """Analyze dataset properties for AI suggestions."""
    try:
        analysis = {
            "has_question_marks": '?' in df.values,
            "special_char_cols": [col for col in df.columns if any(c in col for c in "#@$%^&* ()")],
            "empty_rows": df.isna().all(axis=1).sum(),
            "missing_cols": df.columns[df.isna().any()].tolist(),
            "numeric_cols": df.select_dtypes(include=['int64', 'float64']).columns.tolist(),
            "cat_cols": df.select_dtypes(include=['object', 'category']).columns.tolist(),
            "duplicates": df.duplicated().sum()
        }
        return analysis
    except Exception as e:
        logger.error(f"Error in analyze_dataset: {str(e)}")
        return {}

@st.cache_data
def get_dataset_summary(df: pd.DataFrame) -> str:
    """Generate a summary of the dataset."""
    try:
        summary = f"Dataset shape: {df.shape}\nColumns: {list(df.columns)}\n"
        for col in df.columns:
            missing = df[col].isna().sum()
            dtype = str(df[col].dtype)
            unique = df[col].nunique()
            summary += f"{col}: {dtype}, {missing} missing, {unique} unique\n"
        return summary
    except Exception as e:
        logger.error(f"Error in get_dataset_summary: {str(e)}")
        return f"Error: {str(e)}"

def get_cleaning_suggestions(df: pd.DataFrame, client: Optional[OpenAI] = None) -> List[Tuple[str, str, float]]:
    """Generate AI-driven cleaning suggestions with explanations and confidence using GPT-4o."""
    if not AI_AVAILABLE or client is None:
        return [("AI unavailable", "No OpenAI API key provided", 0.2)]

    try:
        analysis = analyze_dataset(df)
        summary = f"Dataset shape: {df.shape}\nColumns: {list(df.columns)}\n"
        for col in df.columns:
            missing = df[col].isna().sum()
            dtype = str(df[col].dtype)
            unique = df[col].nunique()
            summary += f"{col}: {dtype}, {missing} missing, {unique} unique\n"

        prompt = f"""
        You are an expert data analyst. Based on this dataset summary, provide specific, actionable cleaning suggestions:
        - Summary: {summary}
        - Analysis: {analysis}
        Use these exact formats only:
        1. "Replace '?' with NaN" - "Converts ambiguous markers to missing values."
        2. "Handle special characters in columns: [list]" - "Improves column name usability."
        3. "Remove fully empty rows" - "Eliminates useless data points."
        4. "Fill missing values in [col] with [mean/median/mode]" - "Restores data completeness."
        5. "Encode categorical column: [col]" - "Prepares for numerical analysis."
        6. "Remove duplicate rows" - "Ensures data uniqueness."
        Provide suggestions only if applicable. Format each as: "Suggestion - Explanation"
        """
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=500
        )
        suggestions_text = response.choices[0].message.content.strip()
        logger.info(f"Raw AI response: {suggestions_text}")

        suggestions = []
        for line in suggestions_text.split("\n"):
            if line.strip() and " - " in line:
                suggestion, explanation = line.split(" - ", 1)
                suggestions.append((suggestion.strip(), explanation.strip(), 0.9))
        return suggestions if suggestions else [("No suggestions", "No issues detected", 0.9)]
    except Exception as e:
        logger.error(f"Error in get_cleaning_suggestions: {str(e)}")
        return [("Error generating suggestions", str(e), 0.2)]

@st.cache_data
def get_insights(df: pd.DataFrame) -> List[str]:
    """Generate natural language insights about the dataset using GPT-4o."""
    if not AI_AVAILABLE:
        return ["AI unavailable: No OpenAI API key provided"]

    try:
        analysis = analyze_dataset(df)
        prompt = f"""
        You are an AI data analyst. Analyze this dataset and provide 3-5 human-readable insights in plain English:
        - Dataset preview (first 10 rows): {df.head(10).to_string()}
        - Analysis: {analysis}
        Examples:
        - "Column X has a strong correlation with Column Y, suggesting a potential relationship."
        - "30% of the data in Column Z is missing, which may impact analysis."
        """
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=300
        )
        return response.choices[0].message.content.strip().split("\n")
    except Exception as e:
        logger.error(f"Error in get_insights: {str(e)}")
        return [f"Error generating insights: {str(e)}"]

@st.cache_data
def get_visualization_suggestions(df: pd.DataFrame) -> List[Dict[str, str]]:
    """Suggest visualizations based on dataset analysis."""
    if not AI_AVAILABLE:
        return []

    try:
        summary = get_dataset_summary(df)
        prompt = f"""
        You are an expert data analyst. Based on this dataset summary, suggest 3 visualizations:
        - Summary: {summary}
        Format each suggestion as:
        - "Chart: [type], X: [col], Y: [col] - Reason: [explanation]"
        Examples:
        - "Chart: Bar, X: category, Y: sales - Reason: Compare sales across categories."
        - "Chart: Line, X: date, Y: revenue - Reason: Visualize revenue trends over time."
        """
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=200
        )
        suggestions_text = response.choices[0].message.content.strip()
        suggestions = []
        for line in suggestions_text.split("\n"):
            if "Chart:" in line:
                parts = line.split(" - Reason: ")
                desc = parts[0].strip()
                reason = parts[1].strip() if len(parts) > 1 else "No reason provided"
                chart_type = desc.split("Chart:")[1].split(",")[0].strip()
                x = desc.split("X:")[1].split(",")[0].strip()
                y = desc.split("Y:")[1].strip()
                suggestions.append({"description": desc, "chart_type": chart_type, "x": x, "y": y, "reason": reason})
        return suggestions
    except Exception as e:
        logger.error(f"Error in get_visualization_suggestions: {str(e)}")
        return []

def apply_cleaning_operations(
    df: Union[pd.DataFrame, Tuple[pd.DataFrame, List[str]]],  # Handle tuple input
    selected_suggestions: List[Tuple[str, str, float]],
    columns_to_drop: List[str],
    options: Dict[str, str] = None,
    replace_value: str = "",
    replace_with: str = "",  # Optional with default
    replace_scope: str = "All columns",  # Optional with default
    encode_cols: List[str] = None,  # Optional with default
    encode_method: str = "Label Encoding",  # Optional with default
    auto_clean: bool = False,
    enrich_col: Optional[str] = None,
    enrich_api_key: Optional[str] = None,
    train_ml: bool = False,
    target_col: Optional[str] = None,
    feature_cols: Optional[List[str]] = None
) -> Tuple[pd.DataFrame, List[str]]:
    """Apply selected cleaning operations to the dataset."""
    # Handle tuple input from previous call
    if isinstance(df, tuple):
        cleaned_df, existing_logs = df
        logs = existing_logs.copy()
    else:
        cleaned_df = df.copy()
        logs = []

    options = options or {}  # Default to empty dict if None
    encode_cols = encode_cols or []  # Default to empty list if None

    try:
        # Manual column dropping
        if columns_to_drop:
            cleaned_df.drop(columns=columns_to_drop, inplace=True, errors='ignore')
            logs.append(f"Dropped columns: {columns_to_drop}")

        # Manual value replacement
        if replace_value and replace_with:
            target_cols = (
                cleaned_df.columns if replace_scope == "All columns" else
                cleaned_df.select_dtypes(include=['int64', 'float64']).columns if replace_scope == "Numeric columns" else
                cleaned_df.select_dtypes(include=['object', 'category']).columns
            )
            replace_count = 0
            for col in target_cols:
                matches = cleaned_df[col] == replace_value
                replace_count += matches.sum()
                if replace_with.lower() == "nan":
                    cleaned_df.loc[matches, col] = np.nan
                else:
                    cleaned_df.loc[matches, col] = replace_with
            logs.append(f"Replaced '{replace_value}' with '{replace_with}' in {replace_scope} ({replace_count} instances)")

        # Apply AI suggestions
        for suggestion, explanation, confidence in selected_suggestions:
            if "Replace '?' with NaN" in suggestion:
                if '?' in cleaned_df.values:
                    cleaned_df.replace('?', np.nan, inplace=True)
                    logs.append(f"Replaced '?' with NaN - {explanation} (Confidence: {confidence:.2f})")
                else:
                    logs.append(f"No '?' found - {explanation} (Confidence: {confidence:.2f})")

            elif "Handle special characters in columns" in suggestion:
                special_cols = [col for col in cleaned_df.columns if any(c in col for c in "#@$%^&* ()")]
                if special_cols:
                    cleaned_df.columns = [re.sub(r'[#@$%^&* ()]', '_', col) for col in cleaned_df.columns]
                    logs.append(f"Replaced special characters with underscores in {special_cols} - {explanation} (Confidence: {confidence:.2f})")
                else:
                    logs.append(f"No special character columns - {explanation} (Confidence: {confidence:.2f})")

            elif "Remove fully empty rows" in suggestion:
                empty_rows = cleaned_df.isna().all(axis=1)
                if empty_rows.any():
                    cleaned_df = cleaned_df[~empty_rows]
                    logs.append(f"Dropped {empty_rows.sum()} empty rows - {explanation} (Confidence: {confidence:.2f})")
                else:
                    logs.append(f"No empty rows - {explanation} (Confidence: {confidence:.2f})")

            elif "Fill missing values" in suggestion:
                col_match = re.search(r"in\s+(\S+)\s+with\s+(mean|median|mode)", suggestion)
                if col_match:
                    col, method = col_match.groups()
                    if col in cleaned_df.columns and cleaned_df[col].isna().any():
                        if method == "mean" and cleaned_df[col].dtype in ['int64', 'float64']:
                            cleaned_df[col].fillna(cleaned_df[col].mean(), inplace=True)
                            logs.append(f"Filled {col} with mean - {explanation} (Confidence: {confidence:.2f})")
                        elif method == "median" and cleaned_df[col].dtype in ['int64', 'float64']:
                            cleaned_df[col].fillna(cleaned_df[col].median(), inplace=True)
                            logs.append(f"Filled {col} with median - {explanation} (Confidence: {confidence:.2f})")
                        elif method == "mode":
                            mode_val = cleaned_df[col].mode().iloc[0] if not cleaned_df[col].mode().empty else np.nan
                            cleaned_df[col].fillna(mode_val, inplace=True)
                            logs.append(f"Filled {col} with mode - {explanation} (Confidence: {confidence:.2f})")
                    else:
                        logs.append(f"No missing values in {col} - {explanation} (Confidence: {confidence:.2f})")

            elif "Encode categorical column" in suggestion:
                col_match = re.search(r"column:\s+(\S+)", suggestion)
                if col_match:
                    col = col_match.group(1)
                    if col in cleaned_df.columns and cleaned_df[col].dtype == 'object':
                        cleaned_df = pd.get_dummies(cleaned_df, columns=[col], prefix=col)
                        logs.append(f"Encoded {col} - {explanation} (Confidence: {confidence:.2f})")
                    else:
                        logs.append(f"No categorical {col} - {explanation} (Confidence: {confidence:.2f})")

            elif "Remove duplicate rows" in suggestion:
                initial_rows = len(cleaned_df)
                cleaned_df.drop_duplicates(inplace=True)
                logs.append(f"Removed {initial_rows - len(cleaned_df)} duplicates - {explanation} (Confidence: {confidence:.2f})")

        return cleaned_df, logs
    except Exception as e:
        logger.error(f"Error in apply_cleaning_operations: {str(e)}")
        return df, [f"Error: {str(e)}"]

def chat_with_gpt(df: pd.DataFrame, message: str, max_tokens: int = 100) -> str:
    """Chat with GPT about the dataset."""
    if not AI_AVAILABLE:
        return "AI unavailable: No OpenAI API key provided"
    
    if "who are you" in message.lower():
        return "I'm your assistant, built for data analysis."
    
    try:
        summary = get_dataset_summary(df)
        prompt = f"Dataset summary:\n{summary}\nQuestion: {message}"
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=max_tokens
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        logger.error(f"Error in chat_with_gpt: {str(e)}")
        return f"Error: {str(e)}"

def get_auto_suggestions(df: pd.DataFrame) -> List[str]:
    """Provide chat auto-suggestions."""
    return [
        "What’s the correlation between the first two numeric columns?",
        "Which column has the most missing values?",
        "Suggest a cleaning step for the dataset."
    ]