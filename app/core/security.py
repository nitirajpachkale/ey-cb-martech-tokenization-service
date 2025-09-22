from datetime import datetime, timedelta
import jwt
from app.core.config import settings

def create_jwt_token(data: dict):
    expire = datetime.utcnow() + timedelta(seconds=settings.JWT_EXPIRE_SECONDS)
    payload = {
        "sub": data.get("username"),
        "tokenization_allowed": data.get("tokenization_allowed"),
        "detokenization_allowed": data.get("detokenization_allowed"),
        "iat": datetime.utcnow().timestamp(),
        "exp": expire.timestamp(),
        "iss": "EY"
    }
    return jwt.encode(payload, settings.APP_SECRET_KEY, algorithm=settings.ALGORITHM)

def decode_jwt_token(token: str):
    return jwt.decode(token, settings.APP_SECRET_KEY, algorithms=settings.ALGORITHM)

def validate_appkey(appkey: str) -> dict:
    if appkey != settings.APP_KEY:
        return {
            "errMsg": "Invalid appkey",
            "status": "-1"
        }
    return None