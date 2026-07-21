from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Wazuh
    wazuh_api_url: str = "https://localhost:55000"
    wazuh_api_user: str = "wazuh"
    wazuh_api_password: str = "wazuh"
    wazuh_verify_tls: bool = False

    # Sécurité du webhook
    webhook_hmac_secret: str

    # TheHive
    thehive_url: str | None = None
    thehive_api_key: str | None = None

    # Threat intel (mon service — priorisation sectorielle)
    threat_intel_url: str
    threat_intel_timeout: float = 5.0

    # VirusTotal (réputation d'IOC)
    virustotal_api_key: str | None = None
    virustotal_timeout: float = 10.0

    # Slack
    slack_bot_token: str | None = None
    slack_alert_channel: str = "#soc-alerts"
    slack_action_channel: str = "#soc-actions"

    # DB
    database_url: str

    # Comportement
    dry_run: bool = True
    approval_timeout_seconds: int = 900
    playbooks_dir: str = "playbooks"

    # Actifs à ne JAMAIS isoler automatiquement
    protected_assets: list[str] = Field(
        default_factory=lambda: ["DC-01", "SQL-PROD-01"]
    )
    privileged_users: list[str] = Field(
        default_factory=lambda: ["Administrator", "svc_backup"]
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()
