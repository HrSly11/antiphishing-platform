"""pg_trgm fuzzy-search indexes

Revision ID: 0003
Revises: 0002
"""
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None

_INDEXES = {
    "ix_trgm_iocs_value": ("iocs", "ioc_value"),
    "ix_trgm_verdicts_sender": ("detection_verdicts", "sender_email"),
    "ix_trgm_verdicts_subject": ("detection_verdicts", "subject"),
    "ix_trgm_samples_domain": ("phishing_samples", "domain"),
}


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")
    for name, (table, column) in _INDEXES.items():
        op.execute(f"CREATE INDEX {name} ON {table} USING gin ({column} gin_trgm_ops)")


def downgrade() -> None:
    for name in _INDEXES:
        op.execute(f"DROP INDEX IF EXISTS {name}")
