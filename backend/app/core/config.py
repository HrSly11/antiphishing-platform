from pathlib import Path
from typing import List

from pydantic_settings import BaseSettings, SettingsConfigDict

# Always load backend/.env regardless of the working directory (uvicorn, alembic, pytest).
ENV_FILE = Path(__file__).resolve().parents[2] / ".env"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=str(ENV_FILE), extra="ignore")

    PROJECT_NAME: str = "Antiphishing Platform"
    API_V1_STR: str = "/api/v1"
    APP_ENV: str = "development"

    DATABASE_URL: str = "postgresql+asyncpg://postgres:12345@127.0.0.1:5432/antiphishing_db"

    # Auth
    SECRET_KEY: str = "change-me-in-env"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_MINUTES: int = 60 * 8
    CORS_ORIGINS: List[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]

    # Service-to-service credentials
    GATEWAY_API_KEY: str = ""  # used by the corporate mail gateway (MTA) to call /analyze-email
    N8N_SERVICE_KEY: str = ""  # used by n8n to call the internal endpoints

    # n8n (outbound, HMAC signed)
    N8N_WEBHOOK_URL: str = "http://localhost:5678/webhook"
    N8N_WEBHOOK_SECRET: str = ""

    # Mail (report delivery)
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM: str = "antiphishing@bancocentral.com"
    SMTP_STARTTLS: bool = True

    # Detection
    ENRICHMENT_ENABLED: bool = True  # DNS / TLS / RDAP lookups with strict timeouts
    ENRICHMENT_TIMEOUT_SECONDS: float = 2.5
    OFFICIAL_DOMAINS: List[str] = ["bancocentral.com"]

    # LLM
    LLM_PROVIDER: str = "ollama"  # ollama | none
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "llama3.2"
    LLM_TIMEOUT_SECONDS: float = 6.0

    # Background workers (SLA escalation, scheduled reports, outbox delivery)
    WORKERS_ENABLED: bool = True
    RATE_LIMIT_PER_MINUTE: int = 600  # per client, mail gateway endpoint
    LOGIN_RATE_LIMIT_PER_MINUTE: int = 20


settings = Settings()
