import base64
import json
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from sqlalchemy import text
from app.core.config import settings
from app.utils.security import encrypt_data
from app.utils.tokens import generate_tokenized_dict, generate_irreversible_token
from app.db.models import DataVault
from app.db.queries.datavault_queries import upsert_datavault_bulk
from app.utils.logger import get_logger

logger = get_logger("bulk_tokenize_service")

def bulk_tokenize(request: dict, db: Session):
    """
    Tokenize a list of PII data entries, encrypt, and store in the database.
    """
    responses = []
    merge_payload = []

    for entry in request.get("kdataList", []):
        try:
            raw_kdata = entry.get("kdata")
            txn_id = entry.get("txn")
            reference_id = entry.get("referenceId")

            if not raw_kdata or not reference_id:
                raise ValueError("Missing required fields: kdata or referenceId")

            decoded_kdata = base64.b64decode(raw_kdata).decode('utf-8')
            pii_json = json.loads(decoded_kdata)

            # Tokenize referenceId and PII JSON
            reference_id_token = generate_irreversible_token(reference_id)
            enc_json = encrypt_data(decoded_kdata)
            pii_token_json = generate_tokenized_dict(pii_json)
            
            merge_payload.append({
                "referenceid": reference_id,
                "referencetoken": reference_id_token,
                "tokenjson": json.dumps(pii_token_json),
                "encjson": enc_json
            })

            responses.append({
                "rtoken": pii_token_json,
                "referenceId": reference_id,
                "referenceToken": reference_id_token,
                "txn": txn_id,
                "status": "1",
                "remark": "SUCCESS: Tokenization successful.",
                "errMsg": None,
                "errCode": None
            })

        except Exception as e:
            responses.append({
                "rtoken": None,
                "referenceId": entry.get("referenceId"),
                "referenceToken": None,
                "txn": entry.get("txn"),
                "status": "-1",
                "remark": "FAILURE: Tokenization failed.",
                "errMsg": str(e),
                "errCode": "PROCESSING_ERROR"
            })
    try:
        if merge_payload:
            upsert_datavault_bulk(db, merge_payload)
            db.commit()
    except Exception as e:  
        db.rollback()
        logger.error('"FAILED: Bulk Tokenization Service Error - Database Error."', extra={ "txn": request.get("txn"), "status_code": 500})
        return {
            "txn": request.get("txn"),
            "status": "-1",
            "remark": "FAILURE: Tokenization failed.",
            "errMsg": str(e),
            "errCode": "DATABASE_ERROR",
            "rtokenList": None
        }
    return {
        "txn": request.get("txn"),
        "status": "1",
        "remark": "SUCCESS: Tokenization successful.",
        "errMsg": None,
        "errCode": None,
        "rtokenList": responses,
    }
