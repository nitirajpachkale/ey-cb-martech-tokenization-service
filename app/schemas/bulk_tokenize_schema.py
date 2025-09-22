from pydantic import BaseModel, Field
from typing import List

class KDataItem(BaseModel):
    kdata: str
    txn: str
    referenceId: str

class BulkTokenizeRequest(BaseModel):
    appkey: str = Field(..., example="a2fb2912248f01c144c6c9f32a465148da903c68817a4ee9378212165aec5417")
    txn: str = Field(..., example="123")
    kdataList: List[KDataItem]
