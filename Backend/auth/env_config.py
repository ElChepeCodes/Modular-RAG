import os
from typing import Optional, TypeVar, List
from pathlib import Path
from dotenv import load_dotenv
import logging

T = TypeVar('T')

class EnvironmentConfig:
    """Gestor de configuración para el servicio de autenticación."""

    def __init__(self, env_file: Optional[str] = None):
        self.logger = logging.getLogger("EnvironmentConfig")
        self._loaded = False
        self.load_environment(env_file)

    def load_environment(self, env_file: Optional[str] = None) -> bool:
        """Carga las variables de entorno desde archivo .env."""
        try:
            self.logger.info("🔍 [ENV_CONFIG] Cargando configuración del servicio de autenticación...")

            if env_file and os.path.exists(env_file):
                load_dotenv(env_file)
            else:
                current_dir = Path.cwd()
                env_paths = [
                    current_dir / ".env",
                    current_dir / ".env.local",  # Prioridad para archivo local
                    current_dir.parent / ".env",
                    Path(__file__).parent / ".env",
                ]

                for env_path in env_paths:
                    if env_path.exists():
                        load_dotenv(env_path)
                        self.logger.info(f"✅ [ENV_CONFIG] Cargado archivo: {env_path}")
                        break

            self._loaded = True
            self.logger.info("✅ [ENV_CONFIG] Configuración cargada exitosamente")
            return True

        except Exception as e:
            self.logger.error(f"❌ [ENV_CONFIG] Error cargando configuración: {e}")
            self._loaded = False
            return False

    def _get_env_str(self, key: str, default: str = "") -> str:
        """Obtiene una variable de entorno como string."""
        raw_value = os.getenv(key)
        if raw_value is None or raw_value.strip() == "":
            return default
        return str(raw_value)

    def _get_env_int(self, key: str, default: int = 0) -> int:
        """Obtiene una variable de entorno como int."""
        raw_value = os.getenv(key)
        if raw_value is None or raw_value.strip() == "":
            return default
        
        try:
            return int(raw_value)
        except (ValueError, TypeError):
            return default

    def _get_env_bool(self, key: str, default: bool = False) -> bool:
        """Obtiene una variable de entorno como bool."""
        raw_value = os.getenv(key)
        if raw_value is None or raw_value.strip() == "":
            return default
        
        return raw_value.lower() in ("true", "1", "yes", "on", "enabled")

    def _get_env_float(self, key: str, default: float = 0.0) -> float:
        """Obtiene una variable de entorno como float."""
        raw_value = os.getenv(key)
        if raw_value is None or raw_value.strip() == "":
            return default
        
        try:
            return float(raw_value)
        except (ValueError, TypeError):
            return default

    def _get_env_list(self, key: str, default: List[str] = []) -> List[str]:
        """Obtiene una variable de entorno como lista separada por comas."""
        if default is None:
            default = []
        
        raw_value = os.getenv(key)
        if raw_value is None or raw_value.strip() == "":
            return default
        
        # Split por comas y limpiar espacios
        items = [item.strip() for item in raw_value.split(",")]
        return [item for item in items if item]  # Filtrar elementos vacíos

    # ============= Configuración básica =============
    
    @property
    def port(self) -> int:
        return self._get_env_int("PORT", 8000)

    @property
    def host(self) -> str:
        return self._get_env_str("HOST", "0.0.0.0")

    @property
    def log_level(self) -> str:
        return self._get_env_str("LOG_LEVEL", "INFO")

    @property
    def debug_mode(self) -> bool:
        return self._get_env_bool("DEBUG_MODE", False)

    @property
    def environment(self) -> str:
        """Detecta si estamos en local o en AWS."""
        # Usar variable de entorno explícita primero
        explicit_env = self._get_env_str("ENVIRONMENT")
        if explicit_env:
            return explicit_env
        
        # Detectar automáticamente basado en ECS_TASK_ARN
        return "aws" if os.getenv("ECS_TASK_ARN") else "local"

    @property
    def is_local(self) -> bool:
        """True si estamos ejecutando localmente."""
        return self.environment == "local"

    @property
    def is_aws(self) -> bool:
        """True si estamos ejecutando en AWS."""
        return self.environment == "aws"

    # ============= Database Configuration =============

    @property
    def database_url(self) -> str:
        return self._get_env_str(
            "DATABASE_URL", 
            "postgresql+asyncpg://user:password@localhost:5432/user_db"
        )

    @property
    def database_echo(self) -> bool:
        return self._get_env_bool("DATABASE_ECHO", False)

    # ============= JWT Configuration =============

    @property
    def secret_key(self) -> str:
        return self._get_env_str(
            "SECRET_KEY", 
            "your-super-secret-key-that-should-be-strong-and-random"
        )

    @property
    def algorithm(self) -> str:
        return self._get_env_str("ALGORITHM", "HS256")

    @property
    def access_token_expire_minutes(self) -> int:
        return self._get_env_int("ACCESS_TOKEN_EXPIRE_MINUTES", 30)

    @property
    def refresh_token_expire_days(self) -> int:
        return self._get_env_int("REFRESH_TOKEN_EXPIRE_DAYS", 7)

    # ============= CORS Configuration =============

    @property
    def allowed_origins(self) -> List[str]:
        return self._get_env_list("ALLOWED_ORIGINS", ["*"])

    @property
    def allowed_methods(self) -> List[str]:
        return self._get_env_list("ALLOWED_METHODS", ["*"])

    @property
    def allowed_headers(self) -> List[str]:
        return self._get_env_list("ALLOWED_HEADERS", ["*"])

    # ============= Rate Limiting =============

    @property
    def rate_limit_enabled(self) -> bool:
        return self._get_env_bool("RATE_LIMIT_ENABLED", True)

    @property
    def rate_limit_requests_per_minute(self) -> int:
        return self._get_env_int("RATE_LIMIT_REQUESTS_PER_MINUTE", 60)

    # ============= Métodos de utilidad =============

    def get_system_info(self) -> dict:
        """Obtiene información del sistema y configuración."""
        return {
            "environment": self.environment,
            "is_local": self.is_local,
            "is_aws": self.is_aws,
            "port": self.port,
            "host": self.host,
            "debug_mode": self.debug_mode,
            "log_level": self.log_level,
            "database_echo": self.database_echo,
            "access_token_expire_minutes": self.access_token_expire_minutes,
            "rate_limit_enabled": self.rate_limit_enabled,
            "cors_origins": len(self.allowed_origins),
        }

    def get_connection_info(self) -> dict:
        """Información de conexión para diagnósticos."""
        return {
            "environment": self.environment,
            "is_local": self.is_local,
            "is_aws": self.is_aws,
            "database_url_masked": self._mask_database_url(),
            "host": self.host,
            "port": self.port,
            "cors_configured": len(self.allowed_origins) > 0,
            "rate_limit_enabled": self.rate_limit_enabled,
        }

    def _mask_database_url(self) -> str:
        """Enmascara credenciales en Database URL."""
        url = self.database_url
        if "@" in url and "://" in url:
            protocol, rest = url.split("://", 1)
            if "@" in rest:
                creds, host_part = rest.split("@", 1)
                if ":" in creds:
                    user, _ = creds.split(":", 1)
                    return f"{protocol}://{user}:***@{host_part}"
        return url[:30] + "..." if len(url) > 30 else url


# Instancia global
config = EnvironmentConfig()


def initialize_environment() -> None:
    """Inicializa el entorno para el servicio de autenticación."""
    logger = logging.getLogger("EnvironmentConfig")
    
    logger.info(f"🚀 [AUTH-SERVICE] Inicializando configuración ({config.environment})...")
    
    # Log información de detección de entorno
    logger.info(f"🔍 [AUTH-SERVICE] Detección de entorno:")
    logger.info(f"  - ECS_TASK_ARN: {os.getenv('ECS_TASK_ARN', 'NO_SET')}")
    logger.info(f"  - ENVIRONMENT var: {os.getenv('ENVIRONMENT', 'NO_SET')}")
    logger.info(f"  - Detected environment: {config.environment}")
    logger.info(f"  - Is local: {config.is_local}")
    logger.info(f"  - Is AWS: {config.is_aws}")
    
    # Log información del sistema
    system_info = config.get_system_info()
    logger.info("📊 [AUTH-SERVICE] Información del sistema:")
    for key, value in system_info.items():
        logger.info(f"  {key}: {value}")
    
    logger.info(f"✅ [AUTH-SERVICE] Configuración inicializada (modo: {config.environment})")