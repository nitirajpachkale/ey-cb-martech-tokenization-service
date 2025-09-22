from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from fastapi.responses import JSONResponse
import json
from app.core.config import settings
from app.utils.security import decrypt_data

class RequestDecryptionMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if settings.ENCRYPTION_ENABLED:
            try:
                body_bytes = await request.body()
                body = json.loads(body_bytes.decode("utf-8"))

                if "encReqData" in body:
                    decrypted_str = decrypt_data(body["encReqData"])
                    decrypted_json = json.loads(decrypted_str)

                    # Cache the decrypted body
                    request._body = json.dumps(decrypted_json).encode("utf-8")

                    # Override the receive method to return the decrypted body
                    async def receive():
                        return {
                            "type": "http.request",
                            "body": request._body,
                            "more_body": False,
                        }

                    request._receive = receive
                else:
                    return JSONResponse(
                        status_code=400,
                        content={"error": "Invalid encrypted request payload", "details": str(e)},
                    )
            except Exception as e:
                return JSONResponse(
                    status_code=400,
                    content={"error": "Invalid encrypted request payload", "details": str(e)},
                )

        return await call_next(request)
