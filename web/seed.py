"""
Seed the database with realistic demo data for UI testing.
Usage: uv run python -m web.seed
"""

import os
import sys
import uuid
from datetime import datetime, timedelta, timezone

from web.config import get_settings
from web.db import init_db, new_session
from web.models import (
    CollectionRun,
    DBGrant,
    GrantActivitySnapshot,
    GrantEvent,
    Tenant,
)


def _ago(**kwargs) -> datetime:
    return datetime.now(timezone.utc) - timedelta(**kwargs)


# Well-known IDs (fake but consistent)
_GRAPH_SP_ID  = "aaaaaaaa-0003-0000-0000-000000000000"
_GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"
_MSFT_TENANT  = "f8cdef31-a31e-4b4a-93e4-5f571e91255a"

# ---------------------------------------------------------------------------
# Vendor catalogue
# Each vendor entry drives grant creation.
#
# Fields:
#   name, app_id, sp_id, publisher_tenant, verified — SP metadata
#   grants — list of per-permission rows:
#       type:       "application" | "delegated"
#       perms:      list[str] — for application, one row per permission;
#                               for delegated, all scopes on one row
#       consent:    "AllPrincipals" | "Principal"
#       run:        1 | 2 | "both" — which run(s) this grant appears in
#       added_in:   2  — emit permission_added event in run 2 (for existing grants)
#   activity_days:  last sign-in days ago (None = never used)
# ---------------------------------------------------------------------------
_VENDORS = [
    {
        "name": "Salesforce CRM",
        "app_id": "sf000001-0000-0000-0000-000000000001",
        "sp_id":  "sf0000sp-0000-0000-0000-000000000001",
        "publisher_tenant": "sf000000-0000-0000-0000-salesforce01",
        "verified": True,
        "grants": [
            {"type": "application", "perms": ["User.Read.All"], "consent": "AllPrincipals", "run": "both"},
            {"type": "application", "perms": ["Mail.Read"],     "consent": "AllPrincipals", "run": "both"},
        ],
        "activity_days": 1,
    },
    {
        "name": "Workday HCM",
        "app_id": "wd000001-0000-0000-0000-000000000001",
        "sp_id":  "wd0000sp-0000-0000-0000-000000000001",
        "publisher_tenant": "wd000000-0000-0000-0000-0workday001",
        "verified": True,
        "grants": [
            {"type": "application", "perms": ["User.Read.All"],       "consent": "AllPrincipals", "run": "both"},
            {"type": "application", "perms": ["Directory.Read.All"],  "consent": "AllPrincipals", "run": "both"},
        ],
        "activity_days": 3,
    },
    {
        "name": "DocuSign",
        "app_id": "ds000001-0000-0000-0000-000000000001",
        "sp_id":  "ds0000sp-0000-0000-0000-000000000001",
        "publisher_tenant": "ds000000-0000-0000-0000-0docusign01",
        "verified": True,
        "grants": [
            {"type": "application", "perms": ["Mail.ReadWrite"],       "consent": "AllPrincipals", "run": "both"},
            # Files.ReadWrite.All was added in run 2 — permission_added event
            {"type": "application", "perms": ["Files.ReadWrite.All"],  "consent": "AllPrincipals", "run": 2, "added_in": 2},
        ],
        "activity_days": 1,
    },
    {
        "name": "Greenhouse ATS",
        "app_id": "gh000001-0000-0000-0000-000000000001",
        "sp_id":  "gh0000sp-0000-0000-0000-000000000001",
        "publisher_tenant": "gh000000-0000-0000-0000-greenhouse01",
        "verified": True,
        "grants": [
            {"type": "application", "perms": ["Directory.Read.All"], "consent": "AllPrincipals", "run": "both"},
            {"type": "application", "perms": ["User.Read.All"],      "consent": "AllPrincipals", "run": "both"},
        ],
        "activity_days": 5,
    },
    {
        "name": "Lattice",
        "app_id": "lt000001-0000-0000-0000-000000000001",
        "sp_id":  "lt0000sp-0000-0000-0000-000000000001",
        "publisher_tenant": "lt000000-0000-0000-0000-00lattice01",
        "verified": False,   # ← unverified publisher
        "grants": [
            {"type": "application", "perms": ["User.ReadWrite.All"], "consent": "AllPrincipals", "run": "both"},
        ],
        "activity_days": 14,
    },
    {
        "name": "Notion",
        "app_id": "no000001-0000-0000-0000-000000000001",
        "sp_id":  "no0000sp-0000-0000-0000-000000000001",
        "publisher_tenant": "no000000-0000-0000-0000-000notion01",
        "verified": False,   # ← unverified publisher
        "grants": [
            {"type": "application", "perms": ["Files.ReadWrite.All"], "consent": "AllPrincipals", "run": "both"},
        ],
        "activity_days": 22,
    },
    {
        "name": "Klue",
        "app_id": "kl000001-0000-0000-0000-000000000001",
        "sp_id":  "kl0000sp-0000-0000-0000-000000000001",
        "publisher_tenant": "kl000000-0000-0000-0000-000000klue1",
        "verified": True,
        "grants": [
            {"type": "application", "perms": ["Directory.Read.All"], "consent": "AllPrincipals", "run": "both"},
        ],
        "activity_days": 30,
    },
    {
        # Supply-chain breach scenario from CLAUDE.md
        "name": "TinyPulse",
        "app_id": "tp000001-0000-0000-0000-000000000001",
        "sp_id":  "tp0000sp-0000-0000-0000-000000000001",
        "publisher_tenant": "tp000000-0000-0000-0000-tinypulse01",
        "verified": False,   # ← unverified
        "grants": [
            {"type": "application", "perms": ["User.Read.All"],    "consent": "AllPrincipals", "run": 2},
            {"type": "application", "perms": ["Mail.ReadWrite"],   "consent": "AllPrincipals", "run": 2},
        ],
        "activity_days": 2,  # recently active despite being new — suspicious
    },
    {
        "name": "Slack Technologies",
        "app_id": "sl000001-0000-0000-0000-000000000001",
        "sp_id":  "sl0000sp-0000-0000-0000-000000000001",
        "publisher_tenant": "sl000000-0000-0000-0000-00000slack1",
        "verified": True,
        "grants": [
            {"type": "delegated", "perms": ["User.Read", "Team.ReadBasic.All"],
             "consent": "AllPrincipals", "run": "both"},
        ],
        "activity_days": 0,  # today
    },
    {
        "name": "Zoom Video Communications",
        "app_id": "zm000001-0000-0000-0000-000000000001",
        "sp_id":  "zm0000sp-0000-0000-0000-000000000001",
        "publisher_tenant": "zm000000-0000-0000-0000-000000zoom1",
        "verified": True,
        "grants": [
            {"type": "delegated", "perms": ["Calendars.ReadWrite"],
             "consent": "Principal",     # ← user-consented + write
             "run": "both"},
        ],
        "activity_days": 45,  # dormant
    },
    {
        "name": "HubSpot",
        "app_id": "hs000001-0000-0000-0000-000000000001",
        "sp_id":  "hs0000sp-0000-0000-0000-000000000001",
        "publisher_tenant": "hs000000-0000-0000-0000-000hubspot1",
        "verified": True,
        "grants": [
            {"type": "delegated", "perms": ["Mail.Read", "Contacts.Read"],
             "consent": "AllPrincipals", "run": "both"},
        ],
        "activity_days": 7,
    },
    {
        "name": "SurveyMonkey",
        "app_id": "sm000001-0000-0000-0000-000000000001",
        "sp_id":  "sm0000sp-0000-0000-0000-000000000001",
        "publisher_tenant": "sm000000-0000-0000-0000-surveymonk1",
        "verified": False,   # ← unverified
        "grants": [
            {"type": "delegated", "perms": ["User.Read"],
             "consent": "Principal",     # ← user-consented
             "run": "both"},
        ],
        "activity_days": 120,  # dormant
    },
    {
        "name": "Figma",
        "app_id": "fg000001-0000-0000-0000-000000000001",
        "sp_id":  "fg0000sp-0000-0000-0000-000000000001",
        "publisher_tenant": "fg000000-0000-0000-0000-000figma001",
        "verified": True,
        "grants": [
            {"type": "delegated", "perms": ["User.Read"],
             "consent": "AllPrincipals",
             "run": 1},   # ← removed in run 2
        ],
        "activity_days": 60,
    },
    {
        "name": "Loom",
        "app_id": "lm000001-0000-0000-0000-000000000001",
        "sp_id":  "lm0000sp-0000-0000-0000-000000000001",
        "publisher_tenant": "lm000000-0000-0000-0000-000000loom1",
        "verified": False,   # ← unverified
        "grants": [
            {"type": "delegated", "perms": ["User.Read", "Files.Read"],
             "consent": "Principal",     # ← user-consented
             "run": "both"},
        ],
        "activity_days": None,  # never used
    },
]


def seed(reset: bool = False) -> None:
    settings = get_settings()
    init_db(settings.database_url)
    db = new_session()

    try:
        existing = db.query(Tenant).filter_by(tenant_id="demo-tenant-0000").first()
        if existing:
            if reset:
                db.delete(existing)
                db.commit()
                print("Existing demo tenant deleted.")
            else:
                print("Demo tenant already exists. Run with --reset to replace it.")
                return

        # Create demo tenant (fake credentials — cannot actually connect)
        tenant = Tenant(
            display_name="Acme Corp (Demo)",
            tenant_id="demo-tenant-0000",
            client_id="demo-client-0000",
            created_at=_ago(days=7),
        )
        tenant.set_secret("demo-secret-not-real", settings.secret_encryption_key)
        db.add(tenant)
        db.flush()

        # ── Run 1: initial state (3 days ago) ─────────────────────────────
        run1_time = _ago(days=3, hours=1)
        run1 = CollectionRun(
            tenant_fk=tenant.id,
            status="success",
            started_at=run1_time,
            finished_at=run1_time + timedelta(seconds=47),
            activity_available=True,
            total_grants=0,  # filled below
            new_grants=0,
            removed_grants=0,
            changed_grants=0,
        )
        db.add(run1)
        db.flush()

        # ── Run 2: change run (2 hours ago) ───────────────────────────────
        run2_time = _ago(hours=2)
        run2 = CollectionRun(
            tenant_fk=tenant.id,
            status="success",
            started_at=run2_time,
            finished_at=run2_time + timedelta(seconds=39),
            activity_available=True,
            total_grants=0,
            new_grants=0,
            removed_grants=0,
            changed_grants=0,
        )
        db.add(run2)
        db.flush()

        # ── Build grants ───────────────────────────────────────────────────
        # grant_id_counter used to generate stable fake graph_ids
        counter = [0]

        def next_graph_id() -> str:
            counter[0] += 1
            return f"demo-grant-{counter[0]:04d}-0000-0000-0000-000000000000"

        # graph_id → DBGrant for upsert logic between runs
        grants_by_gid: dict[str, DBGrant] = {}

        run1_count = run2_count = 0
        run2_new = run2_removed = run2_changed = 0

        for vendor in _VENDORS:
            for g_spec in vendor["grants"]:
                run_presence = g_spec["run"]
                in_run1 = run_presence in (1, "both")
                in_run2 = run_presence in (2, "both")
                added_in_run2 = g_spec.get("added_in") == 2  # permission_added event

                gid = next_graph_id()

                if in_run1 and not added_in_run2:
                    # Create grant, first seen in run 1
                    db_grant = DBGrant(
                        tenant_fk=tenant.id,
                        graph_id=gid,
                        grant_type=g_spec["type"],
                        client_sp_id=vendor["sp_id"],
                        client_app_id=vendor["app_id"],
                        client_display_name=vendor["name"],
                        client_publisher_tenant_id=vendor["publisher_tenant"],
                        client_verified_publisher=vendor["verified"],
                        client_account_enabled=True,
                        resource_sp_id=_GRAPH_SP_ID,
                        resource_display_name="Microsoft Graph",
                        permissions=g_spec["perms"],
                        consent_type=g_spec["consent"],
                        consented_by_user_id=(
                            "user-0001-demo" if g_spec["consent"] == "Principal" else None
                        ),
                        created_at=_ago(days=90) if g_spec["type"] == "application" else None,
                        first_seen_at=run1_time,
                        last_seen_run_id=run2.id if in_run2 else run1.id,
                        is_active=in_run2,
                    )
                    db.add(db_grant)
                    db.flush()
                    grants_by_gid[gid] = db_grant

                    db.add(GrantEvent(run_id=run1.id, grant_id=db_grant.id, event_type="new"))
                    run1_count += 1

                    if in_run2:
                        run2_count += 1
                    else:
                        # Removed in run 2
                        db.add(GrantEvent(run_id=run2.id, grant_id=db_grant.id, event_type="removed"))
                        run2_removed += 1

                elif in_run2 and not in_run1:
                    # New in run 2 (or permission added in run 2)
                    db_grant = DBGrant(
                        tenant_fk=tenant.id,
                        graph_id=gid,
                        grant_type=g_spec["type"],
                        client_sp_id=vendor["sp_id"],
                        client_app_id=vendor["app_id"],
                        client_display_name=vendor["name"],
                        client_publisher_tenant_id=vendor["publisher_tenant"],
                        client_verified_publisher=vendor["verified"],
                        client_account_enabled=True,
                        resource_sp_id=_GRAPH_SP_ID,
                        resource_display_name="Microsoft Graph",
                        permissions=g_spec["perms"],
                        consent_type=g_spec["consent"],
                        consented_by_user_id=(
                            "user-0001-demo" if g_spec["consent"] == "Principal" else None
                        ),
                        created_at=run2_time if g_spec["type"] == "application" else None,
                        first_seen_at=run2_time,
                        last_seen_run_id=run2.id,
                        is_active=True,
                    )
                    db.add(db_grant)
                    db.flush()
                    grants_by_gid[gid] = db_grant

                    if added_in_run2:
                        db.add(GrantEvent(
                            run_id=run2.id, grant_id=db_grant.id,
                            event_type="permission_added",
                            detail={"permissions": g_spec["perms"]},
                        ))
                        run2_changed += 1
                    else:
                        db.add(GrantEvent(run_id=run2.id, grant_id=db_grant.id, event_type="new"))
                        run2_new += 1
                    run2_count += 1

        # ── Activity snapshots ─────────────────────────────────────────────
        # Build per-vendor activity once, apply to all grants for that vendor
        vendor_activity: dict[str, datetime | None] = {}
        for vendor in _VENDORS:
            days = vendor["activity_days"]
            vendor_activity[vendor["sp_id"]] = _ago(days=days) if days is not None else None

        def add_activity(run_id: int) -> None:
            seen_sps: set[str] = set()
            for db_grant in grants_by_gid.values():
                if db_grant.last_seen_run_id == run_id or (
                    run_id == run1.id and db_grant.first_seen_at <= run1_time + timedelta(hours=1)
                ):
                    sp_id = db_grant.client_sp_id
                    if sp_id in seen_sps:
                        continue
                    seen_sps.add(sp_id)
                    last = vendor_activity.get(sp_id)
                    db.add(GrantActivitySnapshot(
                        run_id=run_id,
                        grant_id=db_grant.id,
                        last_sign_in=last,
                        last_app_only_client=last if db_grant.grant_type == "application" else None,
                        last_delegated_client=last if db_grant.grant_type == "delegated" else None,
                    ))

        add_activity(run1.id)
        add_activity(run2.id)

        # ── Update run summary counts ──────────────────────────────────────
        run1.total_grants = run1_count
        run1.new_grants = run1_count
        run1.removed_grants = 0
        run1.changed_grants = 0

        run2.total_grants = run2_count
        run2.new_grants = run2_new
        run2.removed_grants = run2_removed
        run2.changed_grants = run2_changed

        db.commit()

        active = sum(1 for g in grants_by_gid.values() if g.is_active)
        print(f"Demo tenant created: 'Acme Corp (Demo)'")
        print(f"  Run 1 ({run1_time.strftime('%Y-%m-%d %H:%M')} UTC): {run1_count} grants")
        print(f"  Run 2 ({run2_time.strftime('%Y-%m-%d %H:%M')} UTC): "
              f"+{run2_new} new, -{run2_removed} removed, ~{run2_changed} changed")
        print(f"  Active grants: {active}")
        print()
        print("Start the app and go to http://localhost:8000")

    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def seed_github(reset: bool = False) -> None:
    """Seed a GitHub demo tenant with realistic GitHub App installations."""
    settings = get_settings()
    init_db(settings.database_url)
    db = new_session()

    try:
        existing = db.query(Tenant).filter_by(tenant_id="acme-corp-demo-gh").first()
        if existing:
            if reset:
                db.delete(existing)
                db.commit()
                print("Existing GitHub demo tenant deleted.")
            else:
                print("GitHub demo tenant already exists. Run with --reset to replace it.")
                return

        tenant = Tenant(
            display_name="Acme Corp (GitHub Demo)",
            tenant_id="acme-corp-demo-gh",
            client_id="",
            platform="github",
            created_at=_ago(days=10),
        )
        tenant.set_secret("ghp_demo_not_real_000000000000000000", settings.secret_encryption_key)
        db.add(tenant)
        db.flush()

        run1_time = _ago(days=4, hours=2)
        run1 = CollectionRun(
            tenant_fk=tenant.id,
            status="success",
            started_at=run1_time,
            finished_at=run1_time + timedelta(seconds=12),
            activity_available=True,
            total_grants=0, new_grants=0, removed_grants=0, changed_grants=0,
        )
        db.add(run1)

        run2_time = _ago(hours=1)
        run2 = CollectionRun(
            tenant_fk=tenant.id,
            status="success",
            started_at=run2_time,
            finished_at=run2_time + timedelta(seconds=10),
            activity_available=True,
            total_grants=0, new_grants=0, removed_grants=0, changed_grants=0,
        )
        db.add(run2)
        db.flush()

        # GitHub App installations.
        # created_at / last_modified_at are set to realistic ages:
        # - Dependabot, GitHub Actions, Snyk: installed >90d ago, never reconfigured
        #   → triggers "never-reconfigured" risk signal
        # - Linear: installed 45d ago, reconfigured 30d ago → no signal
        # - Datadog: recently reconfigured (permission added in run2) → no signal
        _apps = [
            {
                "install_id": 10001,
                "slug": "dependabot",
                "name": "Dependabot",
                "verified": True,
                "perms": ["contents:read", "metadata:read", "security_events:write"],
                "created_ago": {"days": 180},
                "modified_offset": timedelta(minutes=2),  # same day → never-reconfigured
                "run": "both",
            },
            {
                "install_id": 10002,
                "slug": "github-actions",
                "name": "GitHub Actions",
                "verified": True,
                "perms": ["actions:write", "checks:write", "contents:write",
                          "deployments:write", "metadata:read"],
                "created_ago": {"days": 150},
                "modified_offset": timedelta(minutes=1),  # never-reconfigured
                "run": "both",
            },
            {
                "install_id": 10003,
                "slug": "linear-app",
                "name": "Linear",
                "verified": True,
                "perms": ["issues:write", "metadata:read", "pull_requests:read"],
                "created_ago": {"days": 45},
                "modified_ago": {"days": 30},   # was reconfigured
                "run": "both",
            },
            {
                "install_id": 10004,
                "slug": "snyk",
                "name": "Snyk",
                "verified": True,
                "perms": ["contents:read", "metadata:read", "security_events:write"],
                "created_ago": {"days": 100},
                "modified_offset": timedelta(seconds=30),  # never-reconfigured
                "run": "both",
            },
            {
                # Datadog: all repos + write added in run 2
                "install_id": 10005,
                "slug": "datadog",
                "name": "Datadog",
                "verified": True,
                "perms_run1": ["all-repositories", "checks:read", "contents:read",
                               "metadata:read", "statuses:read"],
                "perms_run2": ["all-repositories", "checks:read", "checks:write",
                               "contents:read", "metadata:read", "statuses:read"],
                "created_ago": {"days": 60},
                "modified_ago": {"hours": 2},   # recent change
                "run": "both",
                "permission_added_in": 2,
            },
            {
                # Suspicious new app: unverified, admin, all repos — appeared in run 2
                "install_id": 10006,
                "slug": "acme-internal-deploy",
                "name": "acme-internal-deploy",
                "verified": False,
                "perms": ["administration:admin", "all-repositories",
                          "contents:write", "metadata:read", "secrets:write"],
                "run": 2,
            },
        ]

        # Fine-grained PATs approved for the org.
        # Includes activity snapshots (token_last_used_at).
        _pats = [
            {
                "pat_id": 20001,
                "owner": "dev-alice",
                "name": "ci-deploy-token",
                "perms": ["contents:write", "issues:read", "metadata:read"],
                "created_ago": {"days": 30},
                "last_used_ago": {"days": 3},   # recently used → green
            },
            {
                "pat_id": 20002,
                "owner": "bob-eng",
                "name": "legacy-integration",
                "perms": ["organization_administration:read", "members:read"],
                "created_ago": {"days": 200},
                "last_used_ago": {"days": 110},  # dormant → red
            },
        ]

        grants_by_install: dict[int, DBGrant] = {}
        r1_count = r2_count = r2_new = r2_removed = r2_changed = 0

        for app in _apps:
            install_id = app["install_id"]
            graph_id = f"gh_{install_id}"
            in_run1 = app["run"] in (1, "both")
            in_run2 = app["run"] in (2, "both")

            perms_run1 = app.get("perms_run1", app.get("perms", []))
            perms_run2 = app.get("perms_run2", app.get("perms", []))
            final_perms = perms_run2 if in_run2 else perms_run1

            created_at = (
                _ago(**app["created_ago"]) if "created_ago" in app
                else (run1_time if in_run1 else run2_time)
            )
            if "modified_offset" in app:
                last_modified_at = created_at + app["modified_offset"]
            elif "modified_ago" in app:
                last_modified_at = _ago(**app["modified_ago"])
            else:
                last_modified_at = run2_time if in_run2 else run1_time

            db_grant = DBGrant(
                tenant_fk=tenant.id,
                graph_id=graph_id,
                grant_type="application",
                client_sp_id=str(install_id),
                client_app_id=app["slug"],
                client_display_name=app["name"],
                client_publisher_tenant_id=None,
                client_verified_publisher=app["verified"],
                client_account_enabled=True,
                resource_sp_id="acme-corp-demo-gh",
                resource_display_name="GitHub / acme-corp-demo-gh",
                permissions=final_perms,
                consent_type="AllPrincipals",
                consented_by_user_id=None,
                created_at=created_at,
                last_modified_at=last_modified_at,
                first_seen_at=run1_time if in_run1 else run2_time,
                last_seen_run_id=run2.id if in_run2 else run1.id,
                is_active=in_run2,
            )
            db.add(db_grant)
            db.flush()
            grants_by_install[install_id] = db_grant

            if in_run1:
                db.add(GrantEvent(run_id=run1.id, grant_id=db_grant.id, event_type="new"))
                r1_count += 1

            if in_run2:
                r2_count += 1
                if not in_run1:
                    db.add(GrantEvent(run_id=run2.id, grant_id=db_grant.id, event_type="new"))
                    r2_new += 1
                elif app.get("permission_added_in") == 2:
                    added = sorted(set(perms_run2) - set(perms_run1))
                    db.add(GrantEvent(
                        run_id=run2.id, grant_id=db_grant.id,
                        event_type="permission_added",
                        detail={"permissions": added},
                    ))
                    r2_changed += 1
            elif in_run1:
                db.add(GrantEvent(run_id=run2.id, grant_id=db_grant.id, event_type="removed"))
                r2_removed += 1

        # PAT grants (delegated, Principal consent, activity snapshots in run2)
        for pat in _pats:
            pat_id = pat["pat_id"]
            graph_id = f"ghpat_{pat_id}"
            owner = pat["owner"]
            name = pat["name"]
            created_at = _ago(**pat["created_ago"])
            last_used = _ago(**pat["last_used_ago"])

            db_pat = DBGrant(
                tenant_fk=tenant.id,
                graph_id=graph_id,
                grant_type="delegated",
                client_sp_id=str(pat_id),
                client_app_id=f"{owner}:{name}",
                client_display_name=f"{name} ({owner})",
                client_publisher_tenant_id=None,
                client_verified_publisher=False,
                client_account_enabled=True,
                resource_sp_id="acme-corp-demo-gh",
                resource_display_name="GitHub / acme-corp-demo-gh",
                permissions=pat["perms"],
                consent_type="Principal",
                consented_by_user_id=owner,
                created_at=created_at,
                last_modified_at=None,
                first_seen_at=run1_time,
                last_seen_run_id=run2.id,
                is_active=True,
            )
            db.add(db_pat)
            db.flush()

            db.add(GrantEvent(run_id=run1.id, grant_id=db_pat.id, event_type="new"))
            r1_count += 1
            r2_count += 1

            # Activity snapshot with real last_used timestamp
            for run_id in (run1.id, run2.id):
                db.add(GrantActivitySnapshot(
                    run_id=run_id,
                    grant_id=db_pat.id,
                    last_sign_in=last_used,
                    last_app_only_client=None,
                    last_delegated_client=last_used,
                ))

        # OAuth App credential authorizations (delegated, Principal consent, no activity).
        _oauth_apps = [
            {
                "cred_id": 30001,
                "app_id": 9001,
                "app_name": "Zapier",
                "owner": "alice",
                "scopes": ["all-repositories", "repo", "gist"],  # broad write
                "created_ago": {"days": 90},
            },
            {
                "cred_id": 30002,
                "app_id": 9001,             # same Zapier app, different user
                "app_name": "Zapier",
                "owner": "bob-eng",
                "scopes": ["all-repositories", "repo", "gist"],
                "created_ago": {"days": 85},
            },
            {
                "cred_id": 30003,
                "app_id": 9002,
                "app_name": "Slack",
                "owner": "alice",
                "scopes": ["repo:status", "notifications"],      # read-only
                "created_ago": {"days": 120},
            },
            {
                "cred_id": 30004,
                "app_id": 9003,
                "app_name": "OldDeployBot",
                "owner": "charlie",
                "scopes": ["all-repositories", "repo", "admin:org", "delete_repo"],  # very broad
                "created_ago": {"days": 400},
            },
        ]

        for oauth in _oauth_apps:
            db_oauth = DBGrant(
                tenant_fk=tenant.id,
                graph_id=f"ghoauth_{oauth['cred_id']}",
                grant_type="delegated",
                client_sp_id=str(oauth["app_id"]),
                client_app_id=str(oauth["app_id"]),
                client_display_name=oauth["app_name"],
                client_publisher_tenant_id=None,
                client_verified_publisher=False,
                client_account_enabled=True,
                resource_sp_id="acme-corp-demo-gh",
                resource_display_name="GitHub / acme-corp-demo-gh",
                permissions=oauth["scopes"],
                consent_type="Principal",
                consented_by_user_id=oauth["owner"],
                created_at=_ago(**oauth["created_ago"]),
                last_modified_at=None,
                first_seen_at=run1_time,
                last_seen_run_id=run2.id,
                is_active=True,
            )
            db.add(db_oauth)
            db.flush()
            db.add(GrantEvent(run_id=run1.id, grant_id=db_oauth.id, event_type="new"))
            r1_count += 1
            r2_count += 1

        run1.total_grants = r1_count
        run1.new_grants = r1_count

        run2.total_grants = r2_count
        run2.new_grants = r2_new
        run2.removed_grants = r2_removed
        run2.changed_grants = r2_changed

        db.commit()

        active = sum(1 for g in grants_by_install.values() if g.is_active)
        print(f"GitHub demo tenant created: 'Acme Corp (GitHub Demo)'")
        print(f"  Run 1 ({run1_time.strftime('%Y-%m-%d %H:%M')} UTC): {r1_count} grants "
              f"({len(_apps)} installs + {len(_pats)} PATs + {len(_oauth_apps)} OAuth)")
        print(f"  Run 2 ({run2_time.strftime('%Y-%m-%d %H:%M')} UTC): "
              f"+{r2_new} new, -{r2_removed} removed, ~{r2_changed} changed")
        print(f"  Active app installations: {active}")

    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


if __name__ == "__main__":
    reset = "--reset" in sys.argv
    seed(reset=reset)
    seed_github(reset=reset)
