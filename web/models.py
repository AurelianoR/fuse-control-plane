from datetime import datetime, timezone

from sqlalchemy import (
    Boolean, Column, DateTime, ForeignKey, Index,
    Integer, JSON, String, Text, UniqueConstraint, text,
)
from sqlalchemy.orm import relationship

from web.db import Base


class TenantGroup(Base):
    __tablename__ = "tenant_groups"

    id = Column(Integer, primary_key=True)
    display_name = Column(String, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    tenants = relationship("Tenant", back_populates="group")


class Tenant(Base):
    __tablename__ = "tenants"

    id = Column(Integer, primary_key=True)
    display_name = Column(String, nullable=False)
    # Azure: tenant GUID. GitHub: org slug.
    tenant_id = Column(String, nullable=False, unique=True)
    # Azure: app registration client ID. GitHub: unused (empty string).
    client_id = Column(String, nullable=False, default="")
    client_secret_enc = Column(Text, nullable=False)
    # "azure" | "github". NULL treated as "azure" for backward compat.
    platform = Column(String, nullable=True)
    group_id = Column(Integer, ForeignKey("tenant_groups.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    group = relationship("TenantGroup", back_populates="tenants")
    runs = relationship(
        "CollectionRun",
        back_populates="tenant",
        order_by="CollectionRun.started_at.desc()",
        cascade="all, delete-orphan",
    )
    grants = relationship("DBGrant", back_populates="tenant", cascade="all, delete-orphan")

    def set_secret(self, plaintext: str, key: str) -> None:
        from web.crypto import encrypt
        self.client_secret_enc = encrypt(plaintext, key)

    def get_secret(self, key: str) -> str:
        from web.crypto import decrypt
        return decrypt(self.client_secret_enc, key)

    @property
    def last_run(self) -> "CollectionRun | None":
        return self.runs[0] if self.runs else None


class CollectionRun(Base):
    __tablename__ = "collection_runs"

    id = Column(Integer, primary_key=True)
    tenant_fk = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    status = Column(String, nullable=False, default="pending")  # pending|running|success|failed
    started_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    finished_at = Column(DateTime, nullable=True)
    error_message = Column(Text, nullable=True)
    activity_available = Column(Boolean, nullable=False, default=False)
    total_grants = Column(Integer, nullable=True)
    new_grants = Column(Integer, nullable=True)
    removed_grants = Column(Integer, nullable=True)
    changed_grants = Column(Integer, nullable=True)

    tenant = relationship("Tenant", back_populates="runs")
    events = relationship("GrantEvent", back_populates="run", cascade="all, delete-orphan")
    activity_snapshots = relationship(
        "GrantActivitySnapshot", back_populates="run", cascade="all, delete-orphan"
    )

    # Prevent concurrent runs per tenant at DB level (SQLite + Postgres partial index)
    __table_args__ = (
        Index(
            "uq_run_active",
            "tenant_fk",
            unique=True,
            sqlite_where=text("status IN ('pending', 'running')"),
            postgresql_where=text("status IN ('pending', 'running')"),
        ),
    )

    @property
    def duration_seconds(self) -> int | None:
        if self.started_at and self.finished_at:
            return int((self.finished_at - self.started_at).total_seconds())
        return None


class DBGrant(Base):
    __tablename__ = "grants"

    id = Column(Integer, primary_key=True)
    tenant_fk = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    graph_id = Column(String, nullable=False)

    grant_type = Column(String, nullable=False)  # delegated | application

    client_sp_id = Column(String, nullable=False)
    client_app_id = Column(String, nullable=False)
    client_display_name = Column(String, nullable=False)
    client_publisher_tenant_id = Column(String, nullable=True)
    client_verified_publisher = Column(Boolean, nullable=False, default=False)
    client_account_enabled = Column(Boolean, nullable=False, default=True)

    resource_sp_id = Column(String, nullable=False)
    resource_display_name = Column(String, nullable=False)

    permissions = Column(JSON, nullable=False, default=list)
    consent_type = Column(String, nullable=True)
    consented_by_user_id = Column(String, nullable=True)

    created_at = Column(DateTime, nullable=True)   # from Graph; null for delegated
    last_modified_at = Column(DateTime, nullable=True)  # GitHub: install updated_at
    first_seen_at = Column(DateTime, nullable=False)
    last_seen_run_id = Column(Integer, ForeignKey("collection_runs.id"), nullable=True)
    is_active = Column(Boolean, nullable=False, default=True)

    tenant = relationship("Tenant", back_populates="grants")
    events = relationship("GrantEvent", back_populates="grant", cascade="all, delete-orphan")
    activity_snapshots = relationship(
        "GrantActivitySnapshot", back_populates="grant", cascade="all, delete-orphan"
    )

    __table_args__ = (
        UniqueConstraint("tenant_fk", "graph_id", name="uq_grant_tenant_graph"),
        Index("ix_grant_tenant_active", "tenant_fk", "is_active"),
        Index("ix_grant_tenant_resource", "tenant_fk", "resource_sp_id"),
    )


class GrantActivitySnapshot(Base):
    __tablename__ = "grant_activity_snapshots"

    id = Column(Integer, primary_key=True)
    run_id = Column(Integer, ForeignKey("collection_runs.id", ondelete="CASCADE"), nullable=False)
    grant_id = Column(Integer, ForeignKey("grants.id", ondelete="CASCADE"), nullable=False)
    last_sign_in = Column(DateTime, nullable=True)
    last_app_only_client = Column(DateTime, nullable=True)
    last_delegated_client = Column(DateTime, nullable=True)

    run = relationship("CollectionRun", back_populates="activity_snapshots")
    grant = relationship("DBGrant", back_populates="activity_snapshots")

    __table_args__ = (
        Index("ix_activity_run_grant", "run_id", "grant_id"),
    )


class GrantEvent(Base):
    __tablename__ = "grant_events"

    id = Column(Integer, primary_key=True)
    run_id = Column(Integer, ForeignKey("collection_runs.id", ondelete="CASCADE"), nullable=False)
    grant_id = Column(Integer, ForeignKey("grants.id", ondelete="CASCADE"), nullable=False)
    event_type = Column(String, nullable=False)  # new|removed|permission_added|permission_removed
    detail = Column(JSON, nullable=True)

    run = relationship("CollectionRun", back_populates="events")
    grant = relationship("DBGrant", back_populates="events")

    __table_args__ = (
        Index("ix_event_run", "run_id"),
    )
