# Documento de Arquitectura: Componentes del Sistema Antiphishing Bancario

## 1. Visión General
El sistema está estructurado bajo los principios de **Arquitectura Hexagonal (Ports & Adapters)** y **CQRS Selectivo**, asegurando desacoplamiento del núcleo de dominio respecto a frameworks (FastAPI, SQLAlchemy, LangChain) e infraestructura de transporte.

## 2. Componentes Principales

```mermaid
graph TD
    subgraph Entrada ["Canales de Entrada"]
        MTA["MTA / Secure Email Gateway (Postfix / O365 Hook)"]
        WebSOC["Portal SOC (React 18 + Vite)"]
        Feeds["ETL Feeds (PhishTank / OpenPhish)"]
    end

    subgraph Core ["Núcleo Hexagonal (FastAPI + Python 3.11)"]
        API["API Routers (v1)"]
        DetectionEngine["Detection Pipeline Engine"]
        ScoringService["Weighted Risk Scoring Service"]
        Heuristics["Heuristics (Homographs, Typosquatting, Entropy)"]
        CommandBus["CQRS Command Bus"]
        QueryBus["CQRS Query Bus"]
    end

    subgraph Adaptadores ["Adaptadores e Infraestructura"]
        DB[(PostgreSQL 16 + pgvector + pg_trgm)]
        Redis[(Redis Cache & Rate Limiting)]
        LLM["LangChain / Ollama Adapter"]
        N8N["n8n SOAR Orchestrator"]
    end

    MTA -->|POST /detection/analyze-email| API
    WebSOC -->|REST API Calls| API
    Feeds -->|Scheduled Jobs| API

    API --> DetectionEngine
    DetectionEngine --> Heuristics
    DetectionEngine --> ScoringService
    DetectionEngine --> LLM
    DetectionEngine --> Redis

    API --> CommandBus
    API --> QueryBus

    CommandBus --> DB
    CommandBus --> N8N
    QueryBus --> DB
    QueryBus --> Redis
```

## 3. Capas del Sistema
- **Dominio Puro (`app/domain`)**: Sin imports de librerías externas. Contiene entidades de negocio, value objects (RiskScore, Severity, Verdict), eventos de dominio y lógica de cálculo algorítmico (Shannon Entropy, Levenshtein, Punycode).
- **Capa de Aplicación (`app/application`)**: CQRS. Comandos para operaciones mutables (crear incidentes, bloquear IOCs) y consultas para lectura de alta velocidad.
- **Adaptadores (`app/adapters`)**: Repositorios async con SQLAlchemy 2.0, conectores a Redis, clientes LLM (Ollama / Azure OpenAI) y webhooks firmados con HMAC para n8n.
- **Capa de Entrada (`app/api`)**: Routers FastAPI, middlewares de correlación de logs, rate limiting y dependencias de inyección de seguridad.
