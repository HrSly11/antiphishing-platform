"""rbac constraints and seed support

Revision ID: 0002
Revises: 0001
"""
from alembic import op
import sqlalchemy as sa

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_check_constraint(
        "ck_users_role_valid", "users", "role IN ('ADMIN','SOC_L2','SOC_L1','AUDITOR','VIEWER')"
    )
    op.create_check_constraint(
        "ck_iocs_list_type_valid", "iocs", "list_type IN ('BLACKLIST','WHITELIST')"
    )
    # Lets the seed runner be idempotent: each named seed is applied once.
    op.create_table(
        "seed_runs",
        sa.Column("name", sa.String(100), primary_key=True),
        sa.Column("applied_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("seed_runs")
    op.drop_constraint("ck_iocs_list_type_valid", "iocs", type_="check")
    op.drop_constraint("ck_users_role_valid", "users", type_="check")
