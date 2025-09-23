import base64
import json
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from app.core.config import settings
from app.utils.security import encrypt_data
from app.utils.tokens import generate_tokenized_dict, generate_irreversible_token
from app.db.models import DataVault
from app.utils.logger import get_logger

logger = get_logger("auth_service")

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
            db.query(DataVault).filter(DataVault.referenceid == reference_id_token).update({
                DataVault.tokenjson: json.dumps(pii_token_json),
                DataVault.encjson: enc_json
            })
            db.commit()
            db_entry = db.query(DataVault).filter(DataVault.referenceid == reference_id_token).first()
            return db_entry
        else:
            raise

def bulk_tokenize(request: dict, db: Session):
    """
    Tokenize a list of PII data entries, encrypt, and store in the database.
    """
    responses = []

    for entry in request.get("kdataList", []):
        try:
            raw_kdata = entry.get("kdata")
            txn_id = entry.get("txn")
            reference_id = entry.get("referenceId")

            if not raw_kdata or not reference_id:
                logger.warning('"Missing required fields: kdata or referenceId"', extra={ "txn": entry.get("txn"), "status_code": 404})
                raise ValueError("Missing required fields: kdata or referenceId")

            decoded_kdata = base64.b64decode(raw_kdata).decode('utf-8')
            pii_json = json.loads(decoded_kdata)

            # Tokenize referenceId and PII JSON
            reference_id_token = generate_irreversible_token(reference_id)
            enc_json = encrypt_data(decoded_kdata)
            pii_token_json = generate_tokenized_dict(pii_json)

            # Store to DB
            store_tokenized_data(
                db=db,
                reference_id=reference_id,
                reference_id_token=reference_id_token,
                pii_token_json=pii_token_json,
                enc_json=enc_json
            )

            # Append success response (keep your original field names)
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
            # Append failure response (keep your original field names)
            logger.error('"FAILED: Bulk Tokenization Service Error."', extra={ "txn": request.get("txn"), "status_code": 500})
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

    return {
        "rtokenList": responses,
        "txn": request.get("txn")
    }
