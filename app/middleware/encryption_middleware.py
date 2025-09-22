from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response, JSONResponse
from fastapi import Request
import json
from app.core.config import settings
from app.utils.security import decrypt_data, encrypt_data

class EncryptionMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if settings.ENCRYPTION_ENABLED:
            print("###### YES")
            try:
                body_bytes = await request.body()
                body = json.loads(body_bytes.decode("utf-8"))

                print("##### MID BODY : ", body)

                if "encReqData" in body:
                    decrypted_json_str = decrypt_data(body["encReqData"])
                    decrypted_json = json.loads(decrypted_json_str)

                    # Reconstruct request stream with decrypted body
                    async def receive():
                        return {
                            "type": "http.request",
                            "body": json.dumps(decrypted_json).encode("utf-8"),
                            "more_body": False,
                        }

                    request._receive = receive  # Override receive method
            except Exception as e:
                return JSONResponse(
                    status_code=400,
                    content={"error": "Invalid encrypted payload", "details": str(e)},
                )

        # Proceed to the actual endpoint
        response = await call_next(request)

        if settings.ENCRYPTION_ENABLED and response.status_code == 200:
            # Read the original response body
            original_body = b""
            async for chunk in response.body_iterator:
                original_body += chunk

            try:
                plain_json = json.loads(original_body.decode("utf-8"))
                encrypted_res_data = encrypt_data(json.dumps(plain_json))
                return JSONResponse(content={"encResData": encrypted_res_data})
            except Exception as e:
                return JSONResponse(
                    status_code=500,
                    content={"error": "Failed to encrypt response", "details": str(e)},
                )

        return response
