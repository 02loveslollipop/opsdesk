import logging
import os

logger = logging.getLogger("opsdesk.security")

class Settings:
    PROJECT_NAME: str = "OpsDesk"
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        "postgresql+psycopg://opsdesk:opsdesk123@localhost:5432/opsdesk"
    )
    JWT_SECRET: str = os.getenv(
        "JWT_SECRET",
        "opsdesk-insecure-presentation-secret-key-2026-minimum-32-chars-ok"
    )
    JWT_ALGORITHM: str = "HS256"
    JWT_ISSUER: str = "opsdesk"
    JWT_AUDIENCE: str = "opsdesk-web"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
    HOST: str = os.getenv("HOST", "127.0.0.1")
    PORT: int = int(os.getenv("PORT", "8000"))
    MAX_REQUEST_SIZE_BYTES: int = int(os.getenv("MAX_REQUEST_SIZE_BYTES", str(1024 * 1024))) # 1MB limit

    def validate_secrets(self):
        if len(self.JWT_SECRET) < 32:
            raise ValueError("CRITICAL SECURITY VIOLATION: JWT_SECRET must be at least 32 characters long.")
        if self.ENVIRONMENT == "production" and "insecure" in self.JWT_SECRET.lower():
            raise ValueError("CRITICAL SECURITY VIOLATION: Default presentation secret cannot be used in production.")

settings = Settings()
# Check configuration health
settings.validate_secrets()
