from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # --- Database ---
    database_url: str = "postgresql+asyncpg://aether:password@localhost:5432/aether_cloud"
    db_pool_size: int = 10
    db_max_overflow: int = 20

    # --- Redis ---
    redis_url: str = "redis://localhost:6379/0"
    redis_password: str = ""   # docker-compose builds REDIS_URL from this; the app itself only reads redis_url

    # --- GitHub App (official Aether app — private key lives here only) ---
    github_app_id: str
    github_private_key: str        # base64-encoded RSA PEM
    github_webhook_secret: str     # HMAC secret registered on the GitHub App

    # --- Admin ---
    # Minimum 32 chars. Generate: python -c "import secrets; print(secrets.token_urlsafe(32))"
    admin_api_key: str

    # --- App ---
    environment: str = "development"
    log_level: str = "INFO"

    # --- Rate limiting ---
    token_rate_limit_per_minute: int = 60   # max token requests per license key per minute

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    @property
    def github_private_key_pem(self) -> str:
        """Decode base64-encoded PEM key."""
        import base64
        try:
            return base64.b64decode(self.github_private_key).decode("utf-8")
        except Exception:
            return self.github_private_key


@lru_cache
def get_settings() -> Settings:
    return Settings()
