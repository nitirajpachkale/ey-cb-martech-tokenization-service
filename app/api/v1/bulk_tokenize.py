from app.core.config import settings
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.schemas.bulk_tokenize_schema import BulkTokenizeRequest
from app.services.bulk_tokenize_service import bulk_tokenize
from app.core.security import validate_appkey

router = APIRouter()

@router.post("/bulk_tokenize")
def bulk_tokenization(
    request: BulkTokenizeRequest,
    db: Session = Depends(get_db)
    ):
    validation_error = validate_appkey(request.appkey)
    if validation_error:
        return validation_error
    response = bulk_tokenize(request.dict(), db)
    return response
