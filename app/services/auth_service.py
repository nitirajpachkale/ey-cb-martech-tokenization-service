import hashlib
from sqlalchemy.orm import Session
from app.db.database import SessionLocal
from app.core.config import settings
from app.core.security import create_jwt_token
from app.db.models import IAMUser
from app.utils.logger import get_logger

# In-memory cache for IAM users
iam_user_cache = {}

logger = get_logger("auth_service")

# -----------------------------
# Utility Functions
# -----------------------------

def hash_password(password: str) -> str:
    """Generate SHA-256 hash of the password."""
    return hashlib.sha256(password.encode()).hexdigest()

def load_iam_users_to_cache(db: Session):
    """Load IAM users from DB into in-memory cache."""
    global iam_user_cache
    users = db.query(IAMUser).all()
    iam_user_cache = {
        user.username: {
            "password_hash": user.password_hash,
            "tokenization_allowed": user.tokenization_allowed == 'Y',
            "detokenization_allowed": user.detokenization_allowed == 'Y'
        }
        for user in users
    }

# -----------------------------
# Main Authentication Function
# -----------------------------

def authenticate_user(auth_data: dict) -> dict:
    try:
        # Load cache if empty
        db = SessionLocal()
        if not iam_user_cache:
            load_iam_users_to_cache(db)

        username = auth_data["username"]
        password_hash = hash_password(auth_data["password"])
        user_record = iam_user_cache.get(username)
        if not user_record or user_record["password_hash"] != password_hash:
            logger.warning('"Missing or Invalid username or password"', extra={ "txn": auth_data["txn"], "status_code": 401})
            return {
                "errMsg": "Invalid username or password",
                "status": "-1"
            }

        # Create JWT token with permissions
        token_payload = {
            "username": username,
            "tokenization_allowed": user_record["tokenization_allowed"],
            "detokenization_allowed": user_record["detokenization_allowed"]
        }

        token = create_jwt_token(token_payload)
        # logger.info('"Authentication Request Processed !!"')
        logger.info('"Authentication Request Processed !!"', extra={ "txn": auth_data["txn"], "status_code": 200 })

        return {
            "ret_data": token,
            "remark": "SUCCESS : JWT Token is generated successfully",
            "errMsg": "NULL",
            "errCode": "NULL",
            "status": "1",
            "txn": auth_data["txn"]
        }
    
    except Exception as e:
        logger.error(f'"Authentication Service Error: {str(e)}"', extra={ "txn": auth_data["txn"], "status_code": 500})
        return {
            "ret_data": None,
            "remark": "FAILED : Authentication Service Error.",
            "errMsg": str(e),
            "errCode": "AUTHENTICATION_ERROR",
            "status": "-1",
            "txn": auth_data["txn"]
        }