from datetime import datetime, timedelta
from typing import Optional, Union
import hashlib
import secrets

from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import and_, update, Column

from .database import get_db, User, RefreshToken
from .schemas import TokenData
from .env_config import config
from .logging_config import get_logger

logger = get_logger(__name__)

# Configuración de password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="auth/login",
    auto_error=False  # No raise automático, lo manejamos manualmente
)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifica una contraseña contra su hash."""
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception as e:
        logger.error(f"❌ [AUTH] Error verificando contraseña: {e}")
        return False


def get_password_hash(password: str) -> str:
    """Genera el hash de una contraseña."""
    try:
        return pwd_context.hash(password)
    except Exception as e:
        logger.error(f"❌ [AUTH] Error generando hash de contraseña: {e}")
        raise


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Crea un token de acceso JWT."""
    try:
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=config.access_token_expire_minutes)
        
        to_encode.update({"exp": expire, "type": "access"})
        encoded_jwt = jwt.encode(to_encode, config.secret_key, algorithm=config.algorithm)
        
        logger.debug(f"🔑 [AUTH] Token de acceso creado para: {data.get('sub', 'unknown')}")
        return encoded_jwt
    except Exception as e:
        logger.error(f"❌ [AUTH] Error creando token de acceso: {e}")
        raise


def create_refresh_token() -> str:
    """Crea un refresh token seguro."""
    try:
        return secrets.token_urlsafe(32)
    except Exception as e:
        logger.error(f"❌ [AUTH] Error creando refresh token: {e}")
        raise


def hash_refresh_token(token: str) -> str:
    """Genera el hash de un refresh token."""
    try:
        return hashlib.sha256(token.encode()).hexdigest()
    except Exception as e:
        logger.error(f"❌ [AUTH] Error generando hash de refresh token: {e}")
        raise


async def store_refresh_token(
    db: AsyncSession, 
    user_id: Column[int], 
    refresh_token: str
) -> RefreshToken:
    """Almacena un refresh token en la base de datos."""
    try:
        token_hash = hash_refresh_token(refresh_token)
        expires_at = datetime.utcnow() + timedelta(days=config.refresh_token_expire_days)
        
        db_refresh_token = RefreshToken(
            user_id=user_id,
            token_hash=token_hash,
            expires_at=expires_at
        )
        
        db.add(db_refresh_token)
        await db.commit()
        await db.refresh(db_refresh_token)
        
        logger.debug(f"🔄 [AUTH] Refresh token almacenado para usuario: {user_id}")
        return db_refresh_token
    except Exception as e:
        logger.error(f"❌ [AUTH] Error almacenando refresh token: {e}")
        await db.rollback()
        raise


async def verify_refresh_token(
    db: AsyncSession, 
    refresh_token: str
) -> Optional[User]:
    """Verifica un refresh token y retorna el usuario asociado."""
    try:
        token_hash = hash_refresh_token(refresh_token)
        
        # Buscar el refresh token en la base de datos
        result = await db.execute(
            select(RefreshToken).where(
                and_(
                    RefreshToken.token_hash == token_hash,
                    RefreshToken.is_revoked == False,
                    RefreshToken.expires_at > datetime.utcnow()
                )
            )
        )
        db_refresh_token = result.scalars().first()
        
        if not db_refresh_token:
            logger.warning("⚠️ [AUTH] Refresh token inválido o expirado")
            return None
        
        # Buscar el usuario asociado
        user_result = await db.execute(
            select(User).where(User.id == db_refresh_token.user_id)
        )
        user = user_result.scalars().first()
        
        if not user or user.is_active is False:
            logger.warning(f"⚠️ [AUTH] Usuario inactivo para refresh token: {db_refresh_token.user_id}")
            return None
        
        logger.debug(f"✅ [AUTH] Refresh token verificado para usuario: {user.username}")
        return user
    except Exception as e:
        logger.error(f"❌ [AUTH] Error verificando refresh token: {e}")
        return None


async def revoke_refresh_token(db: AsyncSession, refresh_token: str) -> bool:
    """Revoca un refresh token."""
    try:
        token_hash = hash_refresh_token(refresh_token)
        
        result = await db.execute(
            update(RefreshToken)
            .where(RefreshToken.token_hash == token_hash)
            .values(is_revoked=True)
        )
        
        if result.rowcount > 0:
            await db.commit()
            logger.debug("🚫 [AUTH] Refresh token revocado exitosamente")
            return True
        
        logger.warning("⚠️ [AUTH] Refresh token no encontrado para revocar")
        return False
    except Exception as e:
        logger.error(f"❌ [AUTH] Error revocando refresh token: {e}")
        await db.rollback()
        return False


async def revoke_all_user_refresh_tokens(db: AsyncSession, user_id: Column[int]) -> bool:
    """Revoca todos los refresh tokens de un usuario."""
    try:
        result = await db.execute(
            update(RefreshToken)
            .where(
                and_(
                    RefreshToken.user_id == user_id,
                    RefreshToken.is_revoked == False
                )
            )
            .values(is_revoked=True)
        )
        
        await db.commit()
        logger.info(f"🚫 [AUTH] {result.rowcount} refresh tokens revocados para usuario: {user_id}")
        return True
    except Exception as e:
        logger.error(f"❌ [AUTH] Error revocando tokens del usuario {user_id}: {e}")
        await db.rollback()
        return False


async def get_current_user(
    token: str = Depends(oauth2_scheme), 
    db: AsyncSession = Depends(get_db)
) -> User:
    """Obtiene el usuario actual basado en el token JWT."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    if not token:
        logger.warning("⚠️ [AUTH] Token no proporcionado")
        raise credentials_exception
    
    try:
        payload = jwt.decode(token, config.secret_key, algorithms=[config.algorithm])
        username: str | None = payload.get("sub")
        token_type: str | None = payload.get("type")
        
        if username is None or token_type != "access":
            logger.warning(f"⚠️ [AUTH] Token inválido - username: {username}, type: {token_type}")
            raise credentials_exception
            
        token_data = TokenData(username=username)
    except JWTError as e:
        logger.warning(f"⚠️ [AUTH] Error decodificando JWT: {e}")
        raise credentials_exception
    except Exception as e:
        logger.error(f"❌ [AUTH] Error inesperado validando token: {e}")
        raise credentials_exception

    # Buscar usuario en la base de datos
    try:
        result = await db.execute(select(User).filter(User.username == token_data.username))
        user = result.scalars().first()
        
        if user is None:
            logger.warning(f"⚠️ [AUTH] Usuario no encontrado: {token_data.username}")
            raise credentials_exception
            
        logger.debug(f"✅ [AUTH] Usuario autenticado: {user.username}")
        return user
    except Exception as e:
        logger.error(f"❌ [AUTH] Error consultando usuario: {e}")
        raise credentials_exception


async def get_current_active_user(current_user: User = Depends(get_current_user)) -> User:
    """Obtiene el usuario actual y verifica que esté activo."""
    if current_user.is_active is False:
        logger.warning(f"⚠️ [AUTH] Usuario inactivo: {current_user.username}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="Inactive user"
        )
    
    logger.debug(f"✅ [AUTH] Usuario activo verificado: {current_user.username}")
    return current_user


async def get_current_verified_user(current_user: User = Depends(get_current_active_user)) -> User:
    """Obtiene el usuario actual y verifica que esté verificado."""
    if current_user.is_verified is False:
        logger.warning(f"⚠️ [AUTH] Usuario no verificado: {current_user.username}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="User not verified"
        )
    
    logger.debug(f"✅ [AUTH] Usuario verificado: {current_user.username}")
    return current_user


async def get_optional_current_user(
    token: str = Depends(oauth2_scheme), 
    db: AsyncSession = Depends(get_db)
) -> Optional[User]:
    """Obtiene el usuario actual si el token es válido, sino retorna None."""
    if not token:
        return None
    
    try:
        return await get_current_user(token, db)
    except HTTPException:
        return None
    except Exception as e:
        logger.warning(f"⚠️ [AUTH] Error obteniendo usuario opcional: {e}")
        return None


async def authenticate_user(db: AsyncSession, username: str, password: str) -> Optional[User]:
    """Autentica a un usuario con username/email y contraseña."""
    try:
        # Buscar por username o email
        result = await db.execute(
            select(User).where(
                (User.username == username) | (User.email == username)
            )
        )
        user = result.scalars().first()
        
        if not user:
            logger.warning(f"⚠️ [AUTH] Usuario no encontrado: {username}")
            return None
        
        if not verify_password(password, str(user.hashed_password)):
            logger.warning(f"⚠️ [AUTH] Contraseña incorrecta para: {username}")
            return None
        
        if user.is_active is False:
            logger.warning(f"⚠️ [AUTH] Usuario inactivo: {username}")
            return None
        
        logger.info(f"✅ [AUTH] Usuario autenticado exitosamente: {user.username}")
        return user
    except Exception as e:
        logger.error(f"❌ [AUTH] Error autenticando usuario: {e}")
        return None


async def update_last_login(db: AsyncSession, user: User) -> None:
    """Actualiza la fecha de último login del usuario."""
    try:
        await db.execute(
            update(User)
            .where(User.id == user.id)
            .values(last_login=datetime.utcnow())
        )
        await db.commit()
        logger.debug(f"📅 [AUTH] Último login actualizado para: {user.username}")
    except Exception as e:
        logger.error(f"❌ [AUTH] Error actualizando último login: {e}")
        await db.rollback()