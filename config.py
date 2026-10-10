"""
CyberGPT Enterprise Configuration
Production-grade settings for the Defensive Cyber Intelligence & SOC Operations Simulator.
"""

import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()


class Config:
    """Base configuration."""
    
    # Security
    SECRET_KEY = os.getenv("SECRET_KEY", "cybergpt-enterprise-secret-key-change-in-production")
    WTF_CSRF_ENABLED = False
    
    # Server Configuration
    HOST = os.getenv("HOST", "0.0.0.0")
    PORT = int(os.getenv("PORT", "5000"))
    FLASK_ENV = os.getenv("FLASK_ENV", "development")
    FLASK_DEBUG = os.getenv("FLASK_DEBUG", "1")
    
    # NVIDIA NIM Configuration
    NVIDIA_BASE_URL = os.getenv("NVIDIA_BASE_URL", "https://integrate.api.nvidia.com/v1")
    NVIDIA_API_KEYS = os.getenv(
        "NVIDIA_API_KEYS",
        "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,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"
    ).split(",")
    
    # Rate Limiting
    RATELIMIT_STORAGE_URL = os.getenv("RATELIMIT_STORAGE_URL", "memory://")
    RATELIMIT_DEFAULT = os.getenv("RATELIMIT_DEFAULT", "300 per day; 60 per hour")
    
    # Session Configuration
    SESSION_TYPE = "memory"
    SESSION_PERMANENT = False
    SESSION_USE_SIGNER = True
    PERMANENT_SESSION_LIFETIME = timedelta(hours=2)
    
    # Logging
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"


class DevelopmentConfig(Config):
    """Development configuration."""
    FLASK_ENV = "development"
    FLASK_DEBUG = True


class ProductionConfig(Config):
    """Production configuration."""
    FLASK_ENV = "production"
    FLASK_DEBUG = False


# Configure the active config
config_by_name = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}

config = config_by_name.get(os.getenv("FLASK_ENV", "default"), DevelopmentConfig)