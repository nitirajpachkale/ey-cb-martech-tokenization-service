from sqlalchemy import Column, String, Text, DateTime, func, CHAR, TIMESTAMP
from app.db.database import Base

class DataVault(Base):
    __tablename__ = "tbl_datavault"

    referenceid = Column(String, primary_key=True, index=True)
    referencetoken = Column(String)
    tokenjson = Column(Text, nullable=False)
    encjson = Column(Text, nullable=False)
    adddate = Column(DateTime(timezone=True), server_default=func.now())
    modifydate = Column(DateTime(timezone=True), onupdate=func.now())

class IAMUser(Base):
    __tablename__ = "TBL_IAM"
    __table_args__ = {"schema": "SCM_TKN"}

    username = Column(String(255), primary_key=True)
    password_hash = Column(String(255), nullable=False)
    tokenization_allowed = Column(CHAR(1), default='N')
    detokenization_allowed = Column(CHAR(1), default='N')
    created_at = Column(TIMESTAMP, server_default=func.current_timestamp())
