"""incident lifecycle and SLA constraints

Revision ID: 0004
Revises: 0003
"""
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_check_constraint(
        "ck_incidents_status_valid", "incidents",
        "status IN ('OPEN','TRIAGED','INVESTIGATING','CONTAINED','CLOSED')",
    )
    op.create_check_constraint(
        "ck_incidents_severity_valid", "incidents", "severity IN ('LOW','MEDIUM','HIGH','CRITICAL')"
    )
    # A closed incident must carry a resolution.
    op.create_check_constraint(
        "ck_incidents_closed_has_resolution", "incidents", "status <> 'CLOSED' OR resolution IS NOT NULL"
    )
    # The SLA worker only scans incidents that are still open.
    op.execute(
        "CREATE INDEX ix_incidents_open_sla ON incidents (sla_deadline) WHERE status <> 'CLOSED'"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_incidents_open_sla")
    op.drop_constraint("ck_incidents_closed_has_resolution", "incidents", type_="check")
    op.drop_constraint("ck_incidents_severity_valid", "incidents", type_="check")
    op.drop_constraint("ck_incidents_status_valid", "incidents", type_="check")
