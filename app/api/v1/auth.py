from fastapi import APIRouter, Request, Depends, Body
from app.schemas.auth_schema import AuthRequest
from app.services.auth_service import authenticate_user
from app.core.security import validate_appkey

router = APIRouter()

@router.post("/authenticate")
async def authenticate(auth_req: AuthRequest = Body(...)):
    validation_error = validate_appkey(auth_req.appkey)
    if validation_error:
        return validation_error
    response = authenticate_user(auth_req.dict())
    return response
