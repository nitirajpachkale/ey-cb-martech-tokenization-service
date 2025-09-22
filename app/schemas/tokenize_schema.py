from pydantic import BaseModel
from typing import Dict

class TokenizeRequest(BaseModel):
    appkey: str
    txn: str
    kdata: str
    referenceId: str

class TokenizeResponse(BaseModel):
    piiTokens: Dict[str, str]
    remark: str
    errMsg: str
    errCode: str
    referenceToken: str
    status: str
    txn: str
