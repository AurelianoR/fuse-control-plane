from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import sessionmaker, DeclarativeBase, Session

_engine = None
_SessionLocal = None


class Base(DeclarativeBase):
    pass


def init_db(database_url: str) -> None:
    global _engine, _SessionLocal

    connect_args = {"check_same_thread": False} if database_url.startswith("sqlite") else {}
    _engine = create_engine(database_url, connect_args=connect_args)

    if database_url.startswith("sqlite"):
        @event.listens_for(_engine, "connect")
        def _set_pragma(dbapi_conn, _):
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA busy_timeout = 5000")
            cur.execute("PRAGMA journal_mode = WAL")
            cur.close()

    _SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=_engine)

    from web.models import Base as ModelBase
    ModelBase.metadata.create_all(bind=_engine)

    from sqlalchemy import inspect as sa_inspect, text as sa_text

    # Migrate: add platform column to tenants if absent.
    t_cols = {c["name"] for c in sa_inspect(_engine).get_columns("tenants")}
    if "platform" not in t_cols:
        with _engine.connect() as conn:
            conn.execute(sa_text("ALTER TABLE tenants ADD COLUMN platform VARCHAR"))
            conn.commit()

    # Migrate: add last_modified_at to grants if absent.
    g_cols = {c["name"] for c in sa_inspect(_engine).get_columns("grants")}
    if "last_modified_at" not in g_cols:
        with _engine.connect() as conn:
            conn.execute(sa_text("ALTER TABLE grants ADD COLUMN last_modified_at DATETIME"))
            conn.commit()

    # Migrate: add group_id to tenants if absent.
    t_cols = {c["name"] for c in sa_inspect(_engine).get_columns("tenants")}
    if "group_id" not in t_cols:
        with _engine.connect() as conn:
            conn.execute(sa_text(
                "ALTER TABLE tenants ADD COLUMN group_id INTEGER REFERENCES tenant_groups(id) ON DELETE SET NULL"
            ))
            conn.commit()


def new_session() -> Session:
    """Create a session for use outside request context (background threads)."""
    if _SessionLocal is None:
        raise RuntimeError("Database not initialized — call init_db() first")
    return _SessionLocal()


def get_db():
    """FastAPI dependency: yields a request-scoped DB session."""
    if _SessionLocal is None:
        raise RuntimeError("Database not initialized — call init_db() first")
    db: Session = _SessionLocal()
    try:
        yield db
    finally:
        db.close()
