import logging
import time
from argon2 import PasswordHasher
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import OperationalError
from app.config import settings
from app.models import Base, User, Ticket

logger = logging.getLogger("opsdesk.db")
ph = PasswordHasher()

# Handle connection string dialect compatibility
db_url = settings.DATABASE_URL
if db_url.startswith("postgresql://") and not db_url.startswith("postgresql+"):
    db_url = db_url.replace("postgresql://", "postgresql+psycopg://", 1)

# SQLAlchemy engine initialization (lazy connection - connects on first query)
engine = create_engine(
    db_url,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=5,
    pool_timeout=10,
    pool_recycle=1800,
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    """Initializes schema and seeds data with retry logic for container startup."""
    global engine, SessionLocal
    max_retries = 10
    retry_delay = 1.5

    for attempt in range(1, max_retries + 1):
        try:
            with engine.connect() as conn:
                logger.info("Database connection established successfully.")
                break
        except (OperationalError, Exception) as exc:
            if attempt < max_retries and "postgresql" in str(engine.url):
                logger.warning(
                    "Database not ready on attempt %d/%d (%s). Retrying in %ss...",
                    attempt,
                    max_retries,
                    exc,
                    retry_delay,
                )
                time.sleep(retry_delay)
            else:
                logger.warning(
                    "PostgreSQL unavailable (%s). Initializing SQLite in-memory fallback.",
                    exc,
                )
                engine = create_engine(
                    "sqlite:///:memory:",
                    connect_args={"check_same_thread": False},
                    pool_pre_ping=True,
                )
                SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
                break

    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        if db.query(User).count() == 0:
            alice = User(username="alice", password=ph.hash("alice123"), role="user")
            bob = User(username="bob", password=ph.hash("bob123"), role="user")
            admin = User(username="admin", password=ph.hash("admin123"), role="admin")
            db.add_all([alice, bob, admin])
            db.commit()

            t1 = Ticket(title="Production API High Latency", description="P99 latency exceeding 800ms in us-east-1 region.", owner_id=alice.id, status="open")
            t2 = Ticket(title="Database Replica Replication Lag", description="Replica 2 lagging by >120 seconds.", owner_id=bob.id, status="in_progress")
            t3 = Ticket(title="SSL/TLS Certificate Renewal", description="Internal wildcard cert *.internal.opsdesk expires in 7 days.", owner_id=alice.id, status="open")
            t4 = Ticket(title="Audit Log Shipper Failure", description="Logstash shipper disk full on syslog node-03.", owner_id=admin.id, status="closed")
            db.add_all([t1, t2, t3, t4])
            db.commit()
            logger.info("Database schema and seed records initialized successfully.")
    finally:
        db.close()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
