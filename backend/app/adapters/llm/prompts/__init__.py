"""Prompt templates package for banking SOC LLM pipelines."""
from app.adapters.llm.prompts.email_classification import (
    EMAIL_CLASSIFICATION_PROMPT,
    detect_prompt_injection,
    sanitize_xml_delimiters,
)
from app.adapters.llm.prompts.incident_summary import INCIDENT_SUMMARY_PROMPT
from app.adapters.llm.prompts.soc_assistant import SOC_ASSISTANT_PROMPT
from app.adapters.llm.prompts.url_analysis import URL_ANALYSIS_PROMPT

__all__ = [
    "EMAIL_CLASSIFICATION_PROMPT",
    "INCIDENT_SUMMARY_PROMPT",
    "SOC_ASSISTANT_PROMPT",
    "URL_ANALYSIS_PROMPT",
    "detect_prompt_injection",
    "sanitize_xml_delimiters",
]
