import logging
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import OperationalError
from app.config import settings
from app.models import Base, User, Ticket

logger = logging.getLogger(__name__)

# Handle connection string dialect compatibility
db_url = settings.DATABASE_URL
if db_url.startswith("postgresql://") and not db_url.startswith("postgresql+"):
    db_url = db_url.replace("postgresql://", "postgresql+psycopg://", 1)

try:
    engine = create_engine(db_url, pool_pre_ping=True)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    # Test connection
    with engine.connect() as conn:
        pass
except (OperationalError, Exception) as exc:
    logger.warning("PostgreSQL connection failed (%s). Falling back to SQLite for local tests.", exc)
    db_url = "sqlite:///./opsdesk_dev.db"
    engine = create_engine(db_url, connect_args={"check_same_thread": False})
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        # Seed users if table is empty
        if db.query(User).count() == 0:
            alice = User(username="alice", password="alice123", role="user")
            bob = User(username="bob", password="bob123", role="user")
            admin = User(username="admin", password="admin123", role="admin")
            db.add_all([alice, bob, admin])
            db.commit()

            t1 = Ticket(title="Production API High Latency", description="P99 latency exceeding 800ms in us-east-1 region.", owner_id=alice.id, status="open")
            t2 = Ticket(title="Database Replica Replication Lag", description="Replica 2 lagging by >120 seconds.", owner_id=bob.id, status="in_progress")
            t3 = Ticket(title="SSL/TLS Certificate Renewal", description="Internal wildcard cert *.internal.opsdesk expires in 7 days.", owner_id=alice.id, status="open")
            t4 = Ticket(title="Audit Log Shipper Failure", description="Logstash shipper disk full on syslog node-03.", owner_id=admin.id, status="closed")
            db.add_all([t1, t2, t3, t4])
            db.commit()
    finally:
        db.close()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
