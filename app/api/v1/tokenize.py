from app.core.config import settings
from fastapi import APIRouter, Depends
from app.schemas.tokenize_schema import TokenizeRequest
from app.services.tokenize_service import tokenize
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.core.security import validate_appkey

router = APIRouter()

@router.post("/tokenize")
def tokenization(
    request: TokenizeRequest,
    db: Session = Depends(get_db)
    ):
    validation_error = validate_appkey(request.appkey)
    if validation_error:
        return validation_error
    response = tokenize(request.dict(), db)
    return response
