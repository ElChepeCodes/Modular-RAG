from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base
from sqlalchemy import Column, Integer, String, Boolean, DateTime, func
from typing import AsyncGenerator

from .env_config import config
from .logging_config import get_logger

logger = get_logger(__name__)

# Crear engine con configuración desde env_config
engine = create_async_engine(
    config.database_url, 
    echo=config.database_echo
)

AsyncSessionLocal = async_sessionmaker(
    autocommit=False, 
    autoflush=False, 
    bind=engine, 
    class_=AsyncSession
)

Base = declarative_base()


class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=True)
    hashed_password = Column(String, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    is_verified = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    last_login = Column(DateTime(timezone=True), nullable=True)
    
    # Campos adicionales para funcionalidad extendida
    full_name = Column(String, nullable=True)
    role = Column(String, default="user", nullable=False)
    
    def __repr__(self):
        return f"<User(id={self.id}, username='{self.username}', email='{self.email}')>"


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=False, index=True)
    token_hash = Column(String, nullable=False, unique=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=False)
    is_revoked = Column(Boolean, default=False, nullable=False)
    
    def __repr__(self):
        return f"<RefreshToken(id={self.id}, user_id={self.user_id}, expires_at={self.expires_at})>"


async def create_db_and_tables():
    """Crea las tablas de la base de datos si no existen."""
    try:
        logger.info("🔧 [DATABASE] Creando tablas de base de datos...")
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("✅ [DATABASE] Tablas creadas exitosamente")
    except Exception as e:
        logger.error(f"❌ [DATABASE] Error creando tablas: {e}")
        raise

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency para obtener una sesión de base de datos."""
    """Dependency para obtener una sesión de base de datos."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception as e:
            logger.error(f"❌ [DATABASE] Error en sesión de base de datos: {e}")
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_database():
    """Inicializa la base de datos y crea las tablas."""
    logger.info("🔄 [DATABASE] Inicializando base de datos...")
    try:
        await create_db_and_tables()
        logger.info(f"✅ [DATABASE] Base de datos inicializada en: {config._mask_database_url()}")
    except Exception as e:
        logger.error(f"❌ [DATABASE] Error inicializando base de datos: {e}")
        raise


async def close_database():
    """Cierra las conexiones de la base de datos."""
    logger.info("🔒 [DATABASE] Cerrando conexiones de base de datos...")
    try:
        await engine.dispose()
        logger.info("✅ [DATABASE] Conexiones cerradas exitosamente")
    except Exception as e:
        logger.error(f"❌ [DATABASE] Error cerrando base de datos: {e}")