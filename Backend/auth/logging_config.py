import logging
import colorlog
from datetime import datetime

def setup_logging(log_level=None, config=None):
    """
    Configura el sistema de logging para el servicio de autenticación.
    Solo logging a consola, sin archivos - AWS CloudWatch maneja la persistencia.
    
    Args:
        log_level: Nivel de logging (opcional, se obtiene de config si no se proporciona)
        config: Instancia de EnvironmentConfig (opcional)
    
    Returns:
        logger: El logger raíz configurado
    """
    # Importar config si no se proporciona
    if config is None:
        try:
            from .env_config import config
        except ImportError:
            # Fallback si env_config no está disponible
            config = None
    
    # Determinar nivel de logging
    if log_level is None:
        if config:
            level_str = config.log_level.upper()
            log_level = getattr(logging, level_str, logging.INFO)
        else:
            log_level = logging.INFO
    
    # Obtener logger raíz
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    
    # Eliminar handlers existentes para evitar duplicados
    if root_logger.handlers:
        for handler in root_logger.handlers:
            root_logger.removeHandler(handler)
    
    # Formato detallado para los logs
    log_format = "%(asctime)s [%(levelname)s] [%(name)s] %(message)s"
    date_format = "%Y-%m-%d %H:%M:%S"
    
    # Formato con colores para la consola
    console_formatter = colorlog.ColoredFormatter(
        "%(log_color)s" + log_format,
        datefmt=date_format,
        log_colors={
            "DEBUG": "cyan",
            "INFO": "green",
            "WARNING": "yellow",
            "ERROR": "red",
            "CRITICAL": "red,bg_white",
        },
    )
    
    # Handler SOLO para consola con colores
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(console_formatter)
    console_handler.setLevel(log_level)
    root_logger.addHandler(console_handler)
    
    # Log de inicio
    root_logger.info("=" * 70)
    root_logger.info(
        f"INICIO SERVICIO AUTH - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    )
    root_logger.info("Logging configurado: SOLO CONSOLA (AWS CloudWatch maneja persistencia)")
    if config:
        root_logger.info(f"Log level: {config.log_level}")
        root_logger.info(f"Debug mode: {config.debug_mode}")
        root_logger.info(f"Environment: {config.environment}")
    root_logger.info("=" * 70)
    
    return root_logger


def get_logger(name):
    """
    Obtiene un logger con el nombre especificado.
    
    Args:
        name: Nombre del logger (generalmente __name__)
    
    Returns:
        Un logger configurado
    """
    return logging.getLogger(name)


def setup_logging_from_config():
    """
    Configura el logging usando la configuración de env_config.
    
    Returns:
        logger: El logger raíz configurado
    """
    try:
        from .env_config import config
        return setup_logging(config=config)
    except ImportError:
        # Fallback si env_config no está disponible
        return setup_logging()