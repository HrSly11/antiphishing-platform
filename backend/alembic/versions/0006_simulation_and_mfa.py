"""simulation campaigns, employee events, and user TOTP MFA columns

Revision ID: 0006
Revises: 0005
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0006"
down_revision: Union[str, None] = "0005"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("mfa_enabled", sa.Boolean(), server_default=sa.text("false"), nullable=False),
    )
    op.add_column(
        "users",
        sa.Column("mfa_secret", sa.String(length=128), nullable=True),
    )

    op.create_table(
        "simulation_campaigns",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("channel", sa.String(length=20), nullable=False),
        sa.Column("template_subject", sa.String(length=300), nullable=False),
        sa.Column("lure_type", sa.String(length=80), nullable=False),
        sa.Column("target_department", sa.String(length=120), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("total_targets", sa.Integer(), nullable=False),
        sa.Column("sent_count", sa.Integer(), nullable=False),
        sa.Column("opened_count", sa.Integer(), nullable=False),
        sa.Column("clicked_count", sa.Integer(), nullable=False),
        sa.Column("reported_count", sa.Integer(), nullable=False),
        sa.Column("click_rate", sa.Float(), nullable=False),
        sa.Column("report_rate", sa.Float(), nullable=False),
        sa.Column("compromise_risk", sa.String(length=20), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("launched_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint(
            "channel IN ('EMAIL','SMS','QR','WEB')",
            name="ck_sim_campaigns_channel_valid",
        ),
        sa.CheckConstraint(
            "status IN ('DRAFT','ACTIVE','COMPLETED')",
            name="ck_sim_campaigns_status_valid",
        ),
    )
    op.create_index(op.f("ix_simulation_campaigns_channel"), "simulation_campaigns", ["channel"], unique=False)
    op.create_index(op.f("ix_simulation_campaigns_created_at"), "simulation_campaigns", ["created_at"], unique=False)
    op.create_index(op.f("ix_simulation_campaigns_name"), "simulation_campaigns", ["name"], unique=False)
    op.create_index(op.f("ix_simulation_campaigns_status"), "simulation_campaigns", ["status"], unique=False)
    op.create_index(
        op.f("ix_simulation_campaigns_target_department"),
        "simulation_campaigns",
        ["target_department"],
        unique=False,
    )

    op.create_table(
        "simulation_events",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("campaign_id", sa.String(length=36), nullable=False),
        sa.Column("employee_email", sa.String(length=255), nullable=False),
        sa.Column("department", sa.String(length=120), nullable=False),
        sa.Column("event_type", sa.String(length=20), nullable=False),
        sa.Column("metadata_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["campaign_id"], ["simulation_campaigns.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint(
            "event_type IN ('SENT','OPENED','CLICKED','REPORTED')",
            name="ck_sim_events_type_valid",
        ),
    )
    op.create_index(op.f("ix_simulation_events_campaign_id"), "simulation_events", ["campaign_id"], unique=False)
    op.create_index(op.f("ix_simulation_events_employee_email"), "simulation_events", ["employee_email"], unique=False)
    op.create_index(op.f("ix_simulation_events_event_type"), "simulation_events", ["event_type"], unique=False)
    op.create_index(op.f("ix_simulation_events_occurred_at"), "simulation_events", ["occurred_at"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_simulation_events_occurred_at"), table_name="simulation_events")
    op.drop_index(op.f("ix_simulation_events_event_type"), table_name="simulation_events")
    op.drop_index(op.f("ix_simulation_events_employee_email"), table_name="simulation_events")
    op.drop_index(op.f("ix_simulation_events_campaign_id"), table_name="simulation_events")
    op.drop_table("simulation_events")

    op.drop_index(op.f("ix_simulation_campaigns_target_department"), table_name="simulation_campaigns")
    op.drop_index(op.f("ix_simulation_campaigns_status"), table_name="simulation_campaigns")
    op.drop_index(op.f("ix_simulation_campaigns_name"), table_name="simulation_campaigns")
    op.drop_index(op.f("ix_simulation_campaigns_created_at"), table_name="simulation_campaigns")
    op.drop_index(op.f("ix_simulation_campaigns_channel"), table_name="simulation_campaigns")
    op.drop_table("simulation_campaigns")

    op.drop_column("users", "mfa_secret")
    op.drop_column("users", "mfa_enabled")
