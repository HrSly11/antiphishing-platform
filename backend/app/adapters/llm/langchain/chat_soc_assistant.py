"""RAG-grounded SOC Analyst Conversational Assistant using LangChain Runnables."""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from langchain_core.output_parsers import StrOutputParser
from langchain_core.runnables import RunnableLambda
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.llm.factory import get_chat_model
from app.adapters.llm.langchain.rag_chain import (
    build_live_soc_context,
    retrieve_knowledge_chunks,
)
from app.adapters.llm.prompts.email_classification import (
    detect_prompt_injection,
    sanitize_xml_delimiters,
)
from app.adapters.llm.prompts.soc_assistant import SOC_ASSISTANT_PROMPT
from app.core.metrics import LLM_CALLS


def _compose_deterministic_answer(
    question: str,
    chunks: List[Dict[str, Any]],
    telemetry: Dict[str, Any],
    injection_detected: bool,
) -> str:
    if injection_detected:
        return (
            "Security Policy Notice: Prompt-injection or policy-override instructions in the query "
            "were rejected. Operating strictly under grounded SOC runbooks (see citations)."
        )

    parts: List[str] = []
    if telemetry.get("connected"):
        by_v = telemetry.get("by_verdict", {})
        parts.append(
            f"Live SOC Telemetry (30d): {telemetry.get('total_analyzed', 0)} messages analyzed "
            f"(MALICIOUS={by_v.get('MALICIOUS', 0)}, SUSPICIOUS={by_v.get('SUSPICIOUS', 0)}, "
            f"CLEAN={by_v.get('CLEAN', 0)}), {telemetry.get('open_incidents', 0)} open incidents "
            f"({telemetry.get('overdue_incidents', 0)} SLA overdue), and {telemetry.get('active_iocs', 0)} active IOCs."
        )

    if chunks:
        parts.append("Grounded Guidance from SOC Knowledge Base:")
        for ch in chunks[:3]:
            snippet = ch["content"].strip().replace("\n", " ")
            if len(snippet) > 360:
                snippet = snippet[:357] + "..."
            parts.append(f"- [{ch['source']}] {snippet}")
    else:
        parts.append(
            "No matching runbook section was found for that specific query in the local knowledge base."
        )

    return "\n".join(parts)


async def ask_soc_assistant(
    question: str,
    session: Optional[AsyncSession] = None,
    top_k: int = 4,
) -> Dict[str, Any]:
    """Answer SOC analyst questions with grounded `docs/...` citations and live DB telemetry."""
    q_clean = (question or "").strip()
    injection_detected, _ = detect_prompt_injection(q_clean)

    chunks = retrieve_knowledge_chunks(q_clean, top_k=top_k)
    citations = list(dict.fromkeys(ch["source"] for ch in chunks))
    telemetry = await build_live_soc_context(session)

    if injection_detected:
        LLM_CALLS.labels(engine="langchain-rag-deterministic").inc()
        return {
            "question": q_clean,
            "answer": _compose_deterministic_answer(q_clean, chunks, telemetry, True),
            "citations": citations or ["docs/runbooks/incident-response.md"],
            "chunks": chunks,
            "live_telemetry": telemetry,
            "injection_detected": True,
            "engine": "langchain-rag-deterministic",
        }

    model, model_engine = get_chat_model(temperature=0.0)
    if model is not None:
        try:
            formatted_chunks = "\n\n".join(
                f"[Source: {c['source']} | Section: {c['heading']}]\n{c['content']}"
                for c in chunks
            )
            chain = SOC_ASSISTANT_PROMPT | model | StrOutputParser()
            llm_answer = await chain.ainvoke(
                {
                    "context_chunks": formatted_chunks[:4000],
                    "telemetry_summary": json.dumps(telemetry, default=str),
                    "question": sanitize_xml_delimiters(q_clean)[:1000],
                }
            )
            if llm_answer and llm_answer.strip():
                LLM_CALLS.labels(engine=model_engine).inc()
                return {
                    "question": q_clean,
                    "answer": llm_answer.strip(),
                    "citations": citations,
                    "chunks": chunks,
                    "live_telemetry": telemetry,
                    "injection_detected": False,
                    "engine": model_engine,
                }
        except Exception:
            pass

    engine_fallback = "langchain-rag-deterministic"
    LLM_CALLS.labels(engine=engine_fallback).inc()
    return {
        "question": q_clean,
        "answer": _compose_deterministic_answer(q_clean, chunks, telemetry, False),
        "citations": citations,
        "chunks": chunks,
        "live_telemetry": telemetry,
        "injection_detected": False,
        "engine": engine_fallback,
    }


soc_assistant_runnable = RunnableLambda(
    lambda payload: ask_soc_assistant(
        question=payload["question"],
        session=payload.get("session"),
        top_k=int(payload.get("top_k", 4)),
    )
)
