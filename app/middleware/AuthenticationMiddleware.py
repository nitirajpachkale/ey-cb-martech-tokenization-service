from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from app.core.security import decode_jwt_token

class AuthenticationMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Skip authentication for /v1/authenticate
        if request.url.path == "/v1/authenticate":
            return await call_next(request)

        # Extract token from Authorization header
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return JSONResponse(status_code=401, content={"detail": "Missing or invalid Authorization header"})

        token = auth_header.split(" ")[1]

        try:
            payload = decode_jwt_token(token)
        except Exception as e:
            return JSONResponse(status_code=401, content={"detail": "Invalid or expired token"})

        # Permission check based on endpoint
        path = request.url.path
        if path in ["/v1/tokenize", "/v1/bulk_tokenize"] and not payload.get("tokenization_allowed"):
            return JSONResponse(status_code=403, content={"detail": "Tokenization access denied"})
        elif path == "/v1/detokenize" and not payload.get("detokenization_allowed"):
            return JSONResponse(status_code=403, content={"detail": "Detokenization access denied"})

        # Attach user info to request state (optional)
        request.state.user = payload.get("username")

        return await call_next(request)
