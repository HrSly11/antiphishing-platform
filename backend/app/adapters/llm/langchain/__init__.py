"""LangChain pipelines, tool-calling URL agent, RAG retriever, and SOC assistant."""
from app.adapters.llm.langchain.chat_soc_assistant import (
    ask_soc_assistant,
    soc_assistant_runnable,
)
from app.adapters.llm.langchain.email_classifier import (
    EmailClassificationResult,
    analyze_email_intent,
    classify_email,
    email_classifier_runnable,
)
from app.adapters.llm.langchain.incident_summarizer import (
    incident_summarizer_runnable,
    summarize_incident,
)
from app.adapters.llm.langchain.rag_chain import (
    rag_retriever_runnable,
    retrieve_knowledge_chunks,
)
from app.adapters.llm.langchain.url_agent import investigate_url, url_agent_runnable

__all__ = [
    "EmailClassificationResult",
    "analyze_email_intent",
    "ask_soc_assistant",
    "classify_email",
    "email_classifier_runnable",
    "incident_summarizer_runnable",
    "investigate_url",
    "rag_retriever_runnable",
    "retrieve_knowledge_chunks",
    "soc_assistant_runnable",
    "summarize_incident",
    "url_agent_runnable",
]
