from pydantic import BaseModel, Field

class AuthRequest(BaseModel):
    txn: str = Field(..., description="Transaction ID")
    appkey: str = Field(..., description="Application Key")
    username: str = Field(..., description="Username")
    password: str = Field(..., description="Password")


class AuthResponse(BaseModel):
    ret_data: str
    remark: str
    errMsg: str
    errCode: str
    status: str
    txn: str
