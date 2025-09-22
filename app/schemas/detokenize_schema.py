from pydantic import BaseModel, Field
from typing import Dict

class DeTokenizeRequest(BaseModel):
    appkey: str = Field(..., description="Valid application key")
    txn: str = Field(..., description="Transaction ID")
    uname: str = Field(..., description="Username (email)")
    upwd: str = Field(..., description="Password (hashed)")
    referenceId: str = Field(..., description="Reference ID token")
