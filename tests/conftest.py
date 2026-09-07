import pytest
from argon2 import PasswordHasher
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.database import get_db
from app.models import Base, User, Ticket
from app.security import create_access_token

ph = PasswordHasher()

# Use isolated in-memory SQLite database for unit and integration testing
TEST_DB_URL = "sqlite:///:memory:"
engine = create_engine(
    TEST_DB_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

@pytest.fixture(scope="function")
def db_session():
    Base.metadata.create_all(bind=engine)
    session = TestingSessionLocal()
    
    # Populate test seeds with Argon2 hashed passwords
    alice = User(username="alice", password=ph.hash("alice123"), role="user")
    bob = User(username="bob", password=ph.hash("bob123"), role="user")
    admin = User(username="admin", password=ph.hash("admin123"), role="admin")
    session.add_all([alice, bob, admin])
    session.commit()

    t1 = Ticket(title="Test Ticket 1", description="Description 1", owner_id=alice.id, status="open")
    session.add(t1)
    session.commit()

    yield session

    session.close()
    Base.metadata.drop_all(bind=engine)

@pytest.fixture(scope="function")
def client(db_session):
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()

@pytest.fixture
def admin_headers(db_session):
    admin = db_session.query(User).filter(User.username == "admin").first()
    token = create_access_token({"sub": str(admin.id), "username": admin.username, "role": admin.role})
    return {"Authorization": f"Bearer {token}"}

@pytest.fixture
def user_headers(db_session):
    alice = db_session.query(User).filter(User.username == "alice").first()
    token = create_access_token({"sub": str(alice.id), "username": alice.username, "role": alice.role})
    return {"Authorization": f"Bearer {token}"}
