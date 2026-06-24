import os
from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Load DATABASE_URL from env or use SQLite as default
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./fuse.db")

# SQLite needs connect_args={"check_same_thread": False}
if DATABASE_URL.startswith("sqlite"):
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
else:
    engine = create_engine(DATABASE_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    from models import Token, Route, SystemSettings, ComplianceFramework
    Base.metadata.create_all(bind=engine)
    
    db = SessionLocal()
    try:
        # Seed SystemSettings if empty
        if db.query(SystemSettings).count() == 0:
            default_settings = SystemSettings(
                id=1,
                default_ttl_minutes=5,
                allowed_scopes="read-only contacts, user-profile",
                enforce_sender_binding=True,
                max_token_usage_limit=1000,
                enabled_frameworks="ISO27001:2022",
                audit_logging_enabled=True,
                fail_strategy="fail-closed"
            )
            db.add(default_settings)
            db.commit()
            print("Database seeded with default system settings.")

        # Seed Compliance Frameworks if empty
        if db.query(ComplianceFramework).count() == 0:
            initial_frameworks = [
                ComplianceFramework(
                    name="ISO27001:2022",
                    description="Information Security Management Systems requirements",
                    score=94,
                    enabled=True
                ),
                ComplianceFramework(
                    name="NIS2",
                    description="High common level of cybersecurity across the Union",
                    score=88,
                    enabled=False
                ),
                ComplianceFramework(
                    name="DORA",
                    description="Digital Operational Resilience Act for the financial sector",
                    score=76,
                    enabled=False
                ),
                ComplianceFramework(
                    name="EU_Data_Act",
                    description="Harmonized rules on fair access to and use of data",
                    score=61,
                    enabled=False
                )
            ]
            db.add_all(initial_frameworks)
            db.commit()
            print("Database seeded with default compliance frameworks.")

        # Seed Tokens if empty
        if db.query(Token).count() == 0:
            initial_tokens = [
                Token(
                    id="tok_az_1",
                    vendor="Datadog Monitoring",
                    provider="azure",
                    resource="Subscription: Prod-EU",
                    scope="ReaderRole",
                    expires_in="45 mins",
                    risk_level="Low",
                    is_critical=False,
                    last_seen=datetime.utcnow().isoformat() + "Z",
                    token_usage=1240,
                    usage_limit=5000,
                    is_revoked=False
                ),
                Token(
                    id="tok_aws_2",
                    vendor="Terraform Cloud Runner",
                    provider="aws",
                    resource="Account: Data-Lake-01",
                    scope="s3:PutObject, s3:ListBucket",
                    expires_in="12 mins",
                    risk_level="Low",
                    is_critical=False,
                    last_seen=datetime.utcnow().isoformat() + "Z",
                    token_usage=890,
                    usage_limit=2000,
                    is_revoked=False
                ),
                Token(
                    id="tok_gcp_3",
                    vendor="External Dev Agency",
                    provider="gcp",
                    resource="Project: ML-Compute-Beta",
                    scope="roles/editor (Over-Permissive)",
                    expires_in="Static Key",
                    risk_level="Critical",
                    is_critical=True,
                    last_seen=datetime.utcnow().isoformat() + "Z",
                    token_usage=12450,
                    usage_limit=1000,
                    is_revoked=False
                ),
                Token(
                    id="tok_az_4",
                    vendor="GitHub Actions CI/CD",
                    provider="azure",
                    resource="Subscription: Staging",
                    scope="ContributorRole",
                    expires_in="58 mins",
                    risk_level="Medium",
                    is_critical=False,
                    last_seen=datetime.utcnow().isoformat() + "Z",
                    token_usage=340,
                    usage_limit=3000,
                    is_revoked=False
                ),
                Token(
                    id="tok_aws_5",
                    vendor="Grafana Observability",
                    provider="aws",
                    resource="Account: Prod-US-East",
                    scope="CloudWatchReadOnly",
                    expires_in="30 mins",
                    risk_level="Low",
                    is_critical=False,
                    last_seen=datetime.utcnow().isoformat() + "Z",
                    token_usage=7800,
                    usage_limit=10000,
                    is_revoked=False
                )
            ]
            db.add_all(initial_tokens)
            db.commit()
            print("Database seeded with initial active tokens.")

        # Seed dynamic target routing if empty
        if db.query(Route).count() == 0:
            initial_routes = [
                Route(
                    vendor="Datadog Monitoring",
                    target_url="https://api.datadoghq.com/v1/input",
                    active=True
                ),
                Route(
                    vendor="Terraform Cloud Runner",
                    target_url="https://app.terraform.io/api/v2",
                    active=True
                ),
                Route(
                    vendor="External Dev Agency",
                    target_url="https://ml-compute.gcp.external-dev.agency/api",
                    active=True
                )
            ]
            db.add_all(initial_routes)
            db.commit()
            print("Database seeded with target routes.")

    except Exception as e:
        db.rollback()
        print(f"Error seeding database: {e}")
    finally:
        db.close()
