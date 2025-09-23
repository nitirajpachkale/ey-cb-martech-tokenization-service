import json
from sqlalchemy.orm import Session
from app.core.config import settings
from app.utils.security import decrypt_data
from app.db.models import DataVault
import hashlib
from app.db.models import IAMUser
from app.utils.logger import get_logger

# In-memory cache for IAM users
iam_user_cache = {}

# -----------------------------
# Utility Functions
# -----------------------------
logger = get_logger("auth_service")

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

def get_encrypted_data_by_reference_id(db: Session, referenceid: str) -> dict:
    """
    Retrieve encrypted data from DataVault by reference ID.
    """
    record = db.query(DataVault).filter(DataVault.referenceid == referenceid).first()
    if not record:
        return {
            "success": False,
            "errMsg": "No record found for the given referenceId"
        }
    return {
        "success": True,
        "data": record.encjson
    }

# -----------------------------
# Main De_Tokenization Function
# -----------------------------

def detokenize(request: dict, db: Session):
    """
    Detokenize by decrypting the stored data for a given referenceId.
    """
    try:
        if not iam_user_cache:
            load_iam_users_to_cache(db)

        user_record = iam_user_cache.get(request.get("uname"))
        if not user_record or user_record["password_hash"] != hash_password(request.get("upwd")):
            logger.warning('"Invalid username or password"', extra={ "txn": request.get("txn"), "status_code": 404})
            return {
                "errMsg": "Invalid username or password",
                "status": "-1"
            }

        # Retrieve encrypted data
        result_db = get_encrypted_data_by_reference_id(db, request.get("referenceId"))
        if result_db["success"]:
            try:
                dec_data = decrypt_data(result_db["data"])
                pii_json = json.loads(dec_data)
                response = {
                    "ret_data": pii_json,
                    "remark": "SUCCESS : Detokenization successful",
                    "errMsg": "NULL",
                    "errCode": "NULL",
                    "status": "1",
                    "txn": request.get("txn")
                }
            except Exception as e:
                logger.error(f'"Decryption or JSON parsing error: {str(e)}"', extra={ "txn": request.get("txn"), "status_code": 500})
                response = {
                    "ret_data": None,
                    "remark": "FAILED : Decryption or JSON parsing error",
                    "errMsg": str(e),
                    "errCode": "DECRYPTION_ERROR",
                    "status": "-1",
                    "txn": request.get("txn")
                }
        else:
            logger.info('"FAILED : No record found"', extra={ "txn": request.get("txn"), "status_code": 200 })
            response = {
                "ret_data": None,
                "remark": "FAILED : No record found",
                "errMsg": result_db["errMsg"],
                "errCode": "NOT_FOUND",
                "status": "-1",
                "txn": request.get("txn")
            }
        return response
    except Exception as e:
        logger.error(f'"De-Tokenizatin Service Error: {str(e)}"', extra={ "txn": request.get("txn"), "status_code": 500})
        return {
            "ret_data": None,
            "remark": "FAILED : De-Tokenizatin Service Error.",
            "errMsg": str(e),
            "errCode": "DE_TOKENIZATION_ERROR",
            "status": "-1",
            "txn": request.get("txn")
        }