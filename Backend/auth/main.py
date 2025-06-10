from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.middleware.cors import CORSMiddleware as FastAPICORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordRequestForm
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import or_
import uvicorn
from typing import List

# Imports locales
from .env_config import config, initialize_environment
from .logging_config import setup_logging_from_config, get_logger
from .database import init_database, close_database, get_db, User
from .middleware import AuthMiddleware, RateLimitMiddleware, SecurityHeadersMiddleware
from .auth import (
    authenticate_user, get_current_user, get_current_active_user, 
    get_current_verified_user, get_optional_current_user,
    create_access_token, create_refresh_token, store_refresh_token,
    verify_refresh_token, revoke_refresh_token, revoke_all_user_refresh_tokens,
    get_password_hash, update_last_login
)
from .schemas import (
    UserCreate, UserLogin, UserResponse, UserUpdate, UserChangePassword,
    LoginResponse, RegisterResponse, MessageResponse, ErrorResponse,
    HealthResponse, RefreshTokenRequest, UsernameCheck, EmailCheck,
    AvailabilityResponse, UserPublic
)

# Configurar logging
logger = setup_logging_from_config()


# ============= Lifecycle Management =============

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle manager para el servicio de autenticación."""
    logger.info("🚀 [AUTH-SERVICE] Iniciando servicio de autenticación...")
    
    try:
        # Inicializar configuración
        initialize_environment()
        
        # Inicializar base de datos
        await init_database()
        
        logger.info("✅ [AUTH-SERVICE] Servicio iniciado exitosamente")
        yield
        
    except Exception as e:
        logger.error(f"❌ [AUTH-SERVICE] Error iniciando servicio: {e}")
        raise
    finally:
        # Cleanup
        logger.info("🔄 [AUTH-SERVICE] Cerrando servicio...")
        try:
            await close_database()
            logger.info("✅ [AUTH-SERVICE] Servicio cerrado exitosamente")
        except Exception as e:
            logger.error(f"❌ [AUTH-SERVICE] Error cerrando servicio: {e}")


# ============= FastAPI App Creation =============

app = FastAPI(
    title="Authentication Service",
    description="Servicio de autenticación con JWT y gestión de usuarios",
    version="1.0.0",
    lifespan=lifespan,
    debug=config.debug_mode
)

# ============= Middleware Setup =============

# Security headers (debe ir primero)
app.add_middleware(SecurityHeadersMiddleware)

# Rate limiting
app.add_middleware(
    RateLimitMiddleware, 
    requests_per_minute=config.rate_limit_requests_per_minute
)

# CORS
app.add_middleware(
    FastAPICORSMiddleware,
    allow_origins=config.allowed_origins,
    allow_credentials=True,
    allow_methods=config.allowed_methods,
    allow_headers=config.allowed_headers,
)

# Auth middleware (debe ir al final)
app.add_middleware(AuthMiddleware)


# ============= Error Handlers =============

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Manejador personalizado para HTTPException."""
    logger.warning(f"⚠️ [HTTP_ERROR] {exc.status_code}: {exc.detail}")
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "detail": exc.detail,
            "error_code": getattr(exc, 'error_code', None)
        }
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Manejador general para excepciones no controladas."""
    logger.error(f"❌ [UNHANDLED_ERROR] {type(exc).__name__}: {str(exc)}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "detail": "Internal server error",
            "error_code": "INTERNAL_ERROR"
        }
    )


# ============= Health Check =============

@app.get("/health", response_model=HealthResponse, tags=["Health"])
async def health_check(db: AsyncSession = Depends(get_db)):
    """Health check del servicio."""
    try:
        # Verificar conexión a base de datos
        await db.execute(select(1))
        db_status = "healthy"
    except Exception as e:
        logger.error(f"❌ [HEALTH] Error conectando a base de datos: {e}")
        db_status = "unhealthy"
    
    return HealthResponse(
        status="healthy" if db_status == "healthy" else "degraded",
        timestamp=datetime.utcnow(),
        environment=config.environment,
        database_status=db_status
    )


@app.get("/", tags=["Root"])
async def root():
    """Endpoint raíz del servicio."""
    return {
        "service": "Authentication Service",
        "version": "1.0.0",
        "status": "running",
        "timestamp": datetime.utcnow(),
        "environment": config.environment
    }


# ============= Authentication Endpoints =============

@app.post("/auth/register", response_model=RegisterResponse, tags=["Authentication"])
async def register_user(
    user_data: UserCreate,
    db: AsyncSession = Depends(get_db)
):
    """Registra un nuevo usuario."""
    try:
        logger.info(f"📝 [REGISTER] Intento de registro para usuario: {user_data.username}")
        
        # Verificar si el usuario ya existe
        existing_user = await db.execute(
            select(User).where(
                or_(
                    User.username == user_data.username,
                    User.email == user_data.email
                )
            )
        )
        
        if existing_user.scalars().first():
            logger.warning(f"⚠️ [REGISTER] Usuario ya existe: {user_data.username}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username or email already registered"
            )
        
        # Crear nuevo usuario
        hashed_password = get_password_hash(user_data.password)
        db_user = User(
            username=user_data.username,
            email=user_data.email,
            full_name=user_data.full_name,
            hashed_password=hashed_password,
            is_active=True,
            is_verified=False  # Requiere verificación por email
        )
        
        db.add(db_user)
        await db.commit()
        await db.refresh(db_user)
        
        logger.info(f"✅ [REGISTER] Usuario registrado exitosamente: {db_user.username}")
        
        return RegisterResponse(
            user=UserResponse.from_orm(db_user),
            message="User registered successfully. Please verify your email."
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ [REGISTER] Error registrando usuario: {e}")
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error creating user"
        )


@app.post("/auth/login", response_model=LoginResponse, tags=["Authentication"])
async def login_user(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db)
):
    """Autentica un usuario y retorna tokens."""
    try:
        logger.info(f"🔐 [LOGIN] Intento de login para: {form_data.username}")
        
        # Autenticar usuario
        user = await authenticate_user(db, form_data.username, form_data.password)
        
        if not user:
            logger.warning(f"⚠️ [LOGIN] Credenciales inválidas para: {form_data.username}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Crear tokens
        access_token_expires = timedelta(minutes=config.access_token_expire_minutes)
        access_token = create_access_token(
            data={"sub": user.username}, 
            expires_delta=access_token_expires
        )
        
        refresh_token = create_refresh_token()
        await store_refresh_token(db, user.id, refresh_token)
        
        # Actualizar último login
        await update_last_login(db, user)
        
        logger.info(f"✅ [LOGIN] Login exitoso para: {user.username}")
        
        return LoginResponse(
            user=UserResponse.from_orm(user),
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
            expires_in=config.access_token_expire_minutes * 60,
            message="Login successful"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ [LOGIN] Error en login: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error during login"
        )


@app.post("/auth/refresh", response_model=LoginResponse, tags=["Authentication"])
async def refresh_token(
    refresh_data: RefreshTokenRequest,
    db: AsyncSession = Depends(get_db)
):
    """Renueva un access token usando un refresh token."""
    try:
        logger.debug("🔄 [REFRESH] Intentando renovar token")
        
        # Verificar refresh token
        user = await verify_refresh_token(db, refresh_data.refresh_token)
        
        if not user:
            logger.warning("⚠️ [REFRESH] Refresh token inválido")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token"
            )
        
        # Crear nuevo access token
        access_token_expires = timedelta(minutes=config.access_token_expire_minutes)
        access_token = create_access_token(
            data={"sub": user.username}, 
            expires_delta=access_token_expires
        )
        
        # Crear nuevo refresh token
        new_refresh_token = create_refresh_token()
        
        # Revocar el refresh token anterior y crear uno nuevo
        await revoke_refresh_token(db, refresh_data.refresh_token)
        await store_refresh_token(db, user.id, new_refresh_token)
        
        logger.debug(f"✅ [REFRESH] Token renovado para: {user.username}")
        
        return LoginResponse(
            user=UserResponse.from_orm(user),
            access_token=access_token,
            refresh_token=new_refresh_token,
            token_type="bearer",
            expires_in=config.access_token_expire_minutes * 60,
            message="Token refreshed successfully"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ [REFRESH] Error renovando token: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error refreshing token"
        )


@app.post("/auth/logout", response_model=MessageResponse, tags=["Authentication"])
async def logout_user(
    refresh_data: RefreshTokenRequest,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Logout de usuario revocando el refresh token."""
    try:
        logger.info(f"👋 [LOGOUT] Logout para usuario: {current_user.username}")
        
        # Revocar el refresh token específico
        await revoke_refresh_token(db, refresh_data.refresh_token)
        
        logger.info(f"✅ [LOGOUT] Logout exitoso para: {current_user.username}")
        
        return MessageResponse(
            message="Logout successful",
            success=True
        )
        
    except Exception as e:
        logger.error(f"❌ [LOGOUT] Error en logout: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error during logout"
        )


@app.post("/auth/logout-all", response_model=MessageResponse, tags=["Authentication"])
async def logout_all_devices(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Logout de todos los dispositivos del usuario."""
    try:
        logger.info(f"🚫 [LOGOUT_ALL] Logout total para usuario: {current_user.username}")
        
        # Revocar todos los refresh tokens del usuario
        await revoke_all_user_refresh_tokens(db, current_user.id)
        
        logger.info(f"✅ [LOGOUT_ALL] Logout total exitoso para: {current_user.username}")
        
        return MessageResponse(
            message="Logged out from all devices successfully",
            success=True
        )
        
    except Exception as e:
        logger.error(f"❌ [LOGOUT_ALL] Error en logout total: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error during logout from all devices"
        )


# ============= User Management Endpoints =============

@app.get("/users/me", response_model=UserResponse, tags=["Users"])
async def get_current_user_info(current_user: User = Depends(get_current_active_user)):
    """Obtiene información del usuario actual."""
    logger.debug(f"👤 [USER_INFO] Información solicitada por: {current_user.username}")
    return UserResponse.from_orm(current_user)


@app.put("/users/me", response_model=UserResponse, tags=["Users"])
async def update_current_user(
    user_update: UserUpdate,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Actualiza información del usuario actual."""
    try:
        logger.info(f"✏️ [USER_UPDATE] Actualización de usuario: {current_user.username}")
        
        # Verificar email único si se está actualizando
        if user_update.email and user_update.email != current_user.email:
            existing_email = await db.execute(
                select(User).where(User.email == user_update.email)
            )
            if existing_email.scalars().first():
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Email already registered"
                )
        
        # Actualizar campos
        for field, value in user_update.dict(exclude_unset=True).items():
            setattr(current_user, field, value)
        
        await db.commit()
        await db.refresh(current_user)
        
        logger.info(f"✅ [USER_UPDATE] Usuario actualizado: {current_user.username}")
        
        return UserResponse.from_orm(current_user)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ [USER_UPDATE] Error actualizando usuario: {e}")
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error updating user"
        )


@app.post("/users/change-password", response_model=MessageResponse, tags=["Users"])
async def change_password(
    password_data: UserChangePassword,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Cambia la contraseña del usuario actual."""
    try:
        logger.info(f"🔐 [CHANGE_PASSWORD] Cambio de contraseña para: {current_user.username}")
        
        # Verificar contraseña actual
        from .auth import verify_password
        if not verify_password(password_data.current_password, current_user.hashed_password):
            logger.warning(f"⚠️ [CHANGE_PASSWORD] Contraseña actual incorrecta: {current_user.username}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Current password is incorrect"
            )
        
        # Actualizar contraseña
        current_user.hashed_password = get_password_hash(password_data.new_password)
        await db.commit()
        
        # Revocar todos los refresh tokens por seguridad
        await revoke_all_user_refresh_tokens(db, int(current_user.id))
        
        logger.info(f"✅ [CHANGE_PASSWORD] Contraseña cambiada para: {current_user.username}")
        
        return MessageResponse(
            message="Password changed successfully. Please login again.",
            success=True
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ [CHANGE_PASSWORD] Error cambiando contraseña: {e}")
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error changing password"
        )


# ============= Utility Endpoints =============

@app.post("/auth/check-username", response_model=AvailabilityResponse, tags=["Utilities"])
async def check_username_availability(
    username_data: UsernameCheck,
    db: AsyncSession = Depends(get_db)
):
    """Verifica si un username está disponible."""
    try:
        existing_user = await db.execute(
            select(User).where(User.username == username_data.username)
        )
        
        available = existing_user.scalars().first() is None
        
        return AvailabilityResponse(
            available=available,
            message="Username is available" if available else "Username is already taken"
        )
        
    except Exception as e:
        logger.error(f"❌ [CHECK_USERNAME] Error verificando username: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error checking username availability"
        )


@app.post("/auth/check-email", response_model=AvailabilityResponse, tags=["Utilities"])
async def check_email_availability(
    email_data: EmailCheck,
    db: AsyncSession = Depends(get_db)
):
    """Verifica si un email está disponible."""
    try:
        existing_user = await db.execute(
            select(User).where(User.email == email_data.email)
        )
        
        available = existing_user.scalars().first() is None
        
        return AvailabilityResponse(
            available=available,
            message="Email is available" if available else "Email is already registered"
        )
        
    except Exception as e:
        logger.error(f"❌ [CHECK_EMAIL] Error verificando email: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error checking email availability"
        )


@app.get("/users", response_model=List[UserPublic], tags=["Users"])
async def list_users(
    skip: int = 0,
    limit: int = 100,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Lista usuarios públicos (solo información básica)."""
    try:
        logger.debug(f"📋 [LIST_USERS] Lista solicitada por: {current_user.username}")
        
        result = await db.execute(
            select(User)
            .where(User.is_active == True)
            .offset(skip)
            .limit(limit)
        )
        users = result.scalars().all()
        
        return [UserPublic.from_orm(user) for user in users]
        
    except Exception as e:
        logger.error(f"❌ [LIST_USERS] Error listando usuarios: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error listing users"
        )


# ============= Main Entry Point =============

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=config.host,
        port=config.port,
        reload=config.debug_mode,
        log_level=config.log_level.lower()
    )