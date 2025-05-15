"""Application settings.

This module provides configuration settings for the application,
loaded from environment variables and configuration files.
"""

from __future__ import annotations

import os
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import yaml
from pydantic import BaseModel, Field, validator


class LogLevel(str, Enum):
    """Log levels."""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class Settings(BaseModel):
    """Application settings."""

    # General settings
    app_name: str = "AGID Security Assessment Methodology"
    app_version: str = "0.1.0"
    debug: bool = Field(default=False)
    log_level: LogLevel = Field(default=LogLevel.INFO)
    log_file: Optional[Path] = None

    # Storage settings
    storage_type: str = Field(default="sqlite")  # "sqlite" or "postgresql"
    sqlite_path: Optional[Path] = None

    # PostgreSQL settings (only used if storage_type is "postgresql")
    pg_host: str = Field(default="localhost")
    pg_port: int = Field(default=5432)
    pg_user: str = Field(default="postgres")
    pg_password: str = Field(default="")
    pg_database: str = Field(default="agid_assessment")

    # Assessment settings
    parallel_checks: bool = Field(default=True)
    max_workers: int = Field(default=10)
    assessment_timeout: int = Field(default=3600)  # Seconds

    # Notification settings
    enable_email_notifications: bool = Field(default=False)
    email_smtp_server: str = Field(default="localhost")
    email_smtp_port: int = Field(default=25)
    email_username: Optional[str] = None
    email_password: Optional[str] = None
    email_from: str = Field(default="agid_assessment@localhost")
    email_to: List[str] = Field(default_factory=list)

    enable_sms_notifications: bool = Field(default=False)
    sms_api_key: Optional[str] = None
    sms_api_secret: Optional[str] = None
    sms_from: Optional[str] = None
    sms_to: List[str] = Field(default_factory=list)

    # Report settings
    report_dir: Optional[Path] = None
    report_format: str = Field(default="pdf")  # "pdf", "html", "json", "csv"

    # Security thresholds
    passing_score_threshold: float = Field(default=70.0)  # 0-100%
    warning_score_threshold: float = Field(default=50.0)  # 0-100%

    # Connection settings
    ssh_timeout: int = Field(default=30)  # Seconds
    ssh_key_path: Optional[Path] = None
    wmi_timeout: int = Field(default=30)  # Seconds

    @validator("log_file", "sqlite_path", "report_dir", "ssh_key_path", pre=True)
    def validate_path(cls, v: Any) -> Optional[Path]:
        """Validate and convert path strings to Path objects.

        Args:
            v: Path value to validate

        Returns:
            Validated Path object or None
        """
        if v is None:
            return None

        if isinstance(v, str):
            return Path(v).expanduser().absolute()

        if isinstance(v, Path):
            return v.expanduser().absolute()

        raise ValueError(f"Invalid path: {v}")

    class Config:
        """Pydantic model configuration."""

        env_prefix = "AGID_"
        env_nested_delimiter = "__"
        use_enum_values = True


def load_settings(config_path: Optional[Union[str, Path]] = None) -> Settings:
    """Load settings from environment variables and configuration file.

    Args:
        config_path: Path to configuration file, or None to use default paths

    Returns:
        Loaded settings
    """
    # Default configuration paths to check
    default_paths = [
        Path.cwd() / "agid_assessment_config.yaml",
        Path.cwd() / "agid_assessment_config.yml",
        Path.home() / ".agid_assessment" / "config.yaml",
        Path.home() / ".agid_assessment" / "config.yml",
        Path("/etc/agid_assessment/config.yaml"),
        Path("/etc/agid_assessment/config.yml"),
    ]

    # Use provided config path if specified
    if config_path:
        config_paths = [Path(config_path)]
    else:
        config_paths = default_paths

    # Try to load from configuration file
    config_data = {}
    for path in config_paths:
        if path.exists() and path.is_file():
            try:
                with path.open("r") as f:
                    config_data = yaml.safe_load(f) or {}
                break
            except Exception as e:
                print(f"Error loading configuration from {path}: {e}")

    # Create settings from environment variables and configuration file
    return Settings(**config_data)


# Create global settings instance
settings = load_settings()


def reload_settings(config_path: Optional[Union[str, Path]] = None) -> Settings:
    """Reload settings from environment variables and configuration file.

    Args:
        config_path: Path to configuration file, or None to use default paths

    Returns:
        Reloaded settings
    """
    global settings
    settings = load_settings(config_path)
    return settings
