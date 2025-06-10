from fastapi import Request, HTTPException, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
import time
from typing import Dict, List
from collections import defaultdict, deque
import asyncio

from .logging_config import get_logger
from .env_config import config

logger = get_logger(__name__)


class AuthMiddleware(BaseHTTPMiddleware):
    """Middleware para manejo de autenticación y logging de requests."""
    
    def __init__(self, app: ASGIApp):
        super().__init__(app)
        
    async def dispatch(self, request: Request, call_next):
        start_time = time.time()
        
        # Log de request entrante
        logger.debug(
            f"🔄 [MIDDLEWARE] {request.method} {request.url.path} "
            f"from {request.client.host if request.client else 'unknown'}"
        )
        
        try:
            response = await call_next(request)
            
            # Calcular tiempo de procesamiento
            process_time = time.time() - start_time
            
            # Log de response
            logger.debug(
                f"✅ [MIDDLEWARE] {request.method} {request.url.path} "
                f"-> {response.status_code} ({process_time:.3f}s)"
            )
            
            # Agregar headers de respuesta
            response.headers["X-Process-Time"] = str(process_time)
            response.headers["X-Request-ID"] = str(id(request))
            
            return response
            
        except Exception as e:
            process_time = time.time() - start_time
            logger.error(
                f"❌ [MIDDLEWARE] {request.method} {request.url.path} "
                f"ERROR: {str(e)} ({process_time:.3f}s)"
            )
            
            # Retornar error genérico para no exponer detalles internos
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={
                    "detail": "Internal server error",
                    "error_code": "INTERNAL_ERROR"
                }
            )


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Middleware para rate limiting por IP."""
    
    def __init__(self, app: ASGIApp, requests_per_minute: int = 60):
        super().__init__(app)
        self.requests_per_minute = requests_per_minute
        self.requests: Dict[str, deque] = defaultdict(deque)
        self.cleanup_interval = 60  # Limpiar cada minuto
        self.last_cleanup = time.time()
        
    async def dispatch(self, request: Request, call_next):
        # Skip rate limiting si está deshabilitado
        if not config.rate_limit_enabled:
            return await call_next(request)
            
        # Obtener IP del cliente
        client_ip = self._get_client_ip(request)
        current_time = time.time()
        
        # Limpiar requests antiguos periódicamente
        if current_time - self.last_cleanup > self.cleanup_interval:
            await self._cleanup_old_requests(current_time)
            self.last_cleanup = current_time
        
        # Limpiar requests antiguos para esta IP
        self._cleanup_ip_requests(client_ip, current_time)
        
        # Verificar rate limit
        if len(self.requests[client_ip]) >= self.requests_per_minute:
            logger.warning(
                f"🚫 [RATE_LIMIT] IP {client_ip} excedió el límite "
                f"({self.requests_per_minute} req/min)"
            )
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "detail": "Too many requests",
                    "error_code": "RATE_LIMIT_EXCEEDED"
                },
                headers={
                    "Retry-After": "60",
                    "X-RateLimit-Limit": str(self.requests_per_minute),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(int(current_time + 60))
                }
            )
        
        # Registrar request
        self.requests[client_ip].append(current_time)
        
        # Continuar con el request
        response = await call_next(request)
        
        # Agregar headers de rate limit
        remaining = max(0, self.requests_per_minute - len(self.requests[client_ip]))
        response.headers["X-RateLimit-Limit"] = str(self.requests_per_minute)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Reset"] = str(int(current_time + 60))
        
        return response
    
    def _get_client_ip(self, request: Request) -> str:
        """Obtiene la IP del cliente considerando proxies."""
        # Verificar headers de proxy comunes
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip
        
        # Fallback a la IP del cliente directo
        return request.client.host if request.client else "unknown"
    
    def _cleanup_ip_requests(self, ip: str, current_time: float):
        """Limpia requests antiguos para una IP específica."""
        cutoff_time = current_time - 60  # Requests más antiguos de 1 minuto
        while self.requests[ip] and self.requests[ip][0] < cutoff_time:
            self.requests[ip].popleft()
    
    async def _cleanup_old_requests(self, current_time: float):
        """Limpia requests antiguos de todas las IPs."""
        cutoff_time = current_time - 60
        ips_to_remove = []
        
        for ip, requests_deque in self.requests.items():
            # Limpiar requests antiguos
            while requests_deque and requests_deque[0] < cutoff_time:
                requests_deque.popleft()
            
            # Marcar IPs sin requests para remover
            if not requests_deque:
                ips_to_remove.append(ip)
        
        # Remover IPs sin requests
        for ip in ips_to_remove:
            del self.requests[ip]
        
        if ips_to_remove:
            logger.debug(f"🧹 [RATE_LIMIT] Limpiadas {len(ips_to_remove)} IPs sin requests")


class CORSMiddleware(BaseHTTPMiddleware):
    """Middleware personalizado para CORS."""
    
    def __init__(
        self, 
        app: ASGIApp, 
        allowed_origins: List[str] = [], 
        allowed_methods: List[str] = [],
        allowed_headers: List[str] = []
    ):
        super().__init__(app)
        self.allowed_origins = allowed_origins or ["*"]
        self.allowed_methods = allowed_methods or ["*"]
        self.allowed_headers = allowed_headers or ["*"]
        
    async def dispatch(self, request: Request, call_next):
        # Manejar preflight requests
        if request.method == "OPTIONS":
            response = JSONResponse(content={})
        else:
            response = await call_next(request)
        
        # Agregar headers CORS
        origin = request.headers.get("origin")
        
        if "*" in self.allowed_origins or (origin and origin in self.allowed_origins):
            response.headers["Access-Control-Allow-Origin"] = origin or "*"
        
        response.headers["Access-Control-Allow-Methods"] = ", ".join(self.allowed_methods)
        response.headers["Access-Control-Allow-Headers"] = ", ".join(self.allowed_headers)
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Max-Age"] = "86400"  # 24 horas
        
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Middleware para agregar headers de seguridad."""
    
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        
        # Headers de seguridad
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        # Solo agregar HSTS en producción
        if not config.debug_mode:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        
        return response