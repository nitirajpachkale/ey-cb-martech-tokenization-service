from app.core.config import settings
from fastapi import APIRouter, Depends
from app.schemas.detokenize_schema import DeTokenizeRequest
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.services.detokenize_service import detokenize
from app.core.security import validate_appkey

router = APIRouter()

@router.post("/detokenize")
def detokenization(
    request: DeTokenizeRequest,
    db: Session = Depends(get_db)
    ):
    validation_error = validate_appkey(request.appkey)
    if validation_error:
        return validation_error
    response = detokenize(request.dict(), db)
    return response
