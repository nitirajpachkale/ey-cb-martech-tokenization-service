# app/middleware/response_encryption.py

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
import json
from app.core.config import settings
from app.utils.security import encrypt_data
import base64

enc_payload_key = base64.b64decode(settings.ENC_PAYLOAD_KEY)

class ResponseEncryptionMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        if settings.ENCRYPTION_ENABLED and response.status_code == 200:
            try:
                body = b""
                async for chunk in response.body_iterator:
                    body += chunk

                data = json.loads(body.decode("utf-8"))
                encrypted_data = encrypt_data(json.dumps(data), enc_payload_key)

                return JSONResponse(content={"encResData": encrypted_data})

            except Exception as e:
                return JSONResponse(
                    status_code=500,
                    content={"error": "Response encryption failed", "details": str(e)},
                )

        return response
