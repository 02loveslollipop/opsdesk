import os

class Settings:
    PROJECT_NAME: str = "OpsDesk"
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        "postgresql+psycopg://opsdesk:opsdesk123@localhost:5432/opsdesk"
    )
    JWT_SECRET: str = os.getenv(
        "JWT_SECRET",
        "opsdesk-insecure-presentation-secret-key-2026"
    )
    JWT_ALGORITHM: str = "HS256"
    JWT_ISSUER: str = "opsdesk"
    JWT_AUDIENCE: str = "opsdesk-web"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    HOST: str = os.getenv("HOST", "127.0.0.1")
    PORT: int = int(os.getenv("PORT", "8000"))

settings = Settings()
