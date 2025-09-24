import base64
import json
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from app.core.config import settings
from app.utils.security import encrypt_data, decrypt_data
from app.utils.tokens import generate_tokenized_dict, generate_irreversible_token
from app.db.models import DataVault
from app.utils.logger import get_logger

logger = get_logger("tokenize_service")

def store_tokenized_data(db: Session, reference_id: str, reference_id_token: str, pii_token_json: dict, enc_json: str):
    """
    Store or update tokenized data in the DataVault table.
    """
    try:
        db_entry = DataVault(
            referenceid=reference_id,
            referencetoken=reference_id_token,
            tokenjson=json.dumps(pii_token_json),
            encjson=enc_json
        )
        db.add(db_entry)
        db.commit()
        db.refresh(db_entry)
        return db_entry
    except IntegrityError as e:
        db.rollback()
        # Handle unique constraint violation (update existing record)
        if 'unique constraint' in str(e.orig).lower():
            db.query(DataVault).filter(DataVault.referenceid == reference_id).update({
                DataVault.tokenjson: json.dumps(pii_token_json),
                DataVault.encjson: enc_json
            })
            db.commit()
            db_entry = db.query(DataVault).filter(DataVault.referenceid == reference_id).first()
            return db_entry
        else:
            raise

def tokenize(request: dict, db: Session):
    """
    Tokenize PII data, encrypt it, and store in the database.
    """
    try:
        # Decode and parse PII data
        decoded_kdata = base64.b64decode(request["kdata"]).decode('utf-8')
        pii_json = json.loads(decoded_kdata)

        # Encrypt the full PII data JSON
        enc_json = encrypt_data(decoded_kdata)

        # Tokenize referenceId and PII JSON
        reference_id = request["referenceId"]
        reference_id_token = generate_irreversible_token(reference_id)
        pii_token_json = generate_tokenized_dict(pii_json)

        # Store in DB
        store_tokenized_data(
            db=db,
            reference_id=reference_id,
            reference_id_token=reference_id_token,
            pii_token_json=pii_token_json,
            enc_json=enc_json
        )

        response = {
            "piiTokens": pii_token_json,
            "remark": "SUCCESS: Tokenization successful.",
            "errMsg": "NULL",
            "errCode": "NULL",
            "referenceId": reference_id,
            "referenceToken": reference_id_token,
            "status": "1",
            "txn": request.get("txn")
        }
        return response

    except Exception as e:
        logger.error('"FAILED: Tokenization Service Error."', extra={ "txn": request.get("txn"), "status_code": 500})
        return {
            "piiTokens": None,
            "remark": "FAILED: Tokenization Service Error.",
            "errMsg": str(e),
            "errCode": "TOKENIZATION_ERROR",
            "referenceId": None,
            "referenceToken": None,
            "status": "-1",
            "txn": request.get("txn")
        }
