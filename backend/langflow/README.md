# LangFlow Visual Prototyping Sandbox (Module 7)

## Overview
`backend/langflow/flows/` stores the version-controlled **LangFlow v1** visual graphs used by SOC AI engineers to prototype prompt templates, prompt-injection delimiters, and tool-calling URL investigation flows before promoting them to production code in `backend/app/adapters/llm/langchain/`.

## Included Flows
1. **`flows/email_classifier_sandbox.json` (`email_classifier_sandbox`)**:
   - **Topology**: `ChatInput` -> `XML Delimiter & Prompt-Injection Guard` -> `Banking SOC Anti-Injection Prompt` -> `OllamaModel (llama3.2)` -> `StructuredOutputComponent` -> `ChatOutput`.
   - **Production Counterpart**: `app/adapters/llm/langchain/email_classifier.py`.
2. **`flows/url_agent_sandbox.json` (`url_agent_sandbox`)**:
   - **Topology**: `ChatInput` + 5 SOC tools (`whois_domain_age_tool`, `dns_lookup_tool`, `tls_certificate_tool`, `pg_trgm_similarity_tool`, `blacklist_lookup_tool`) + `OllamaModel (llama3.2)` -> `ToolCallingAgent` -> `ChatOutput`.
   - **Production Counterpart**: `app/adapters/llm/langchain/url_agent.py`.

## Running Locally with Docker
```bash
docker run --rm -p 7860:7860 langflowai/langflow:latest
```
Import either JSON file from `backend/langflow/flows/` in the LangFlow UI (`Upload a flow`) and point `OllamaModel.base_url` to `http://host.docker.internal:11434`.
