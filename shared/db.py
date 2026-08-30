from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from shared.config import settings


class Base(DeclarativeBase):
    pass


# SQLite's default driver refuses to use a connection from any thread but
# the one that opened it — a problem the moment a real connection pool
# hands connections to FastAPI's worker threads. There's no equivalent
# restriction (or connect_args key) for Postgres, so this only applies
# there.
_connect_args = (
    {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
)
engine = create_engine(settings.database_url, pool_pre_ping=True, connect_args=_connect_args)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


def get_session() -> Generator[Session, None, None]:
    """FastAPI dependency / general-purpose session context."""
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
