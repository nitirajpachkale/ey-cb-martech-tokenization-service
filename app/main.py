from fastapi import FastAPI
from app.api.v1 import auth, tokenize, detokenize, bulk_tokenize
from app.middleware.AuthenticationMiddleware import AuthenticationMiddleware
from app.middleware.request_decryption import RequestDecryptionMiddleware
from app.middleware.response_encryption import ResponseEncryptionMiddleware
from fastapi import Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from app.core.config import settings
from app.utils.security import encrypt_data
import json
from app.utils.logger import setup_logging

listener = setup_logging()

app = FastAPI(title="Tokenization App")

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    errors = exc.errors()
    missing_fields = [
        err['loc'][-1]
        for err in errors
        if err['type'] == 'missing' and err['msg'].lower().startswith('field required')
    ]

    response_data = {
            "status": "-1",
            "errMsg": f"Missing required fields: {', '.join(missing_fields)}",
            "ret_data": None,
            "remark": "Validation Failed",
            "errCode": "VALIDATION_ERROR",
            "txn": None
        }
    
    if settings.ENCRYPTION_ENABLED:
        response_data = {
            "encResData": encrypt_data(json.dumps(response_data))
            }

    return JSONResponse(
        status_code = 422,
        content = response_data
    )

app.add_middleware(AuthenticationMiddleware)
app.add_middleware(RequestDecryptionMiddleware)
app.add_middleware(ResponseEncryptionMiddleware)


app.include_router(auth.router, prefix="/v1")
app.include_router(tokenize.router, prefix="/v1")
app.include_router(detokenize.router, prefix="/v1")
app.include_router(bulk_tokenize.router, prefix="/v1")
