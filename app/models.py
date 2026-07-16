from sqlalchemy import Column, Integer, String, ForeignKey
from .database import Base

class Tokens(Base):
    __tablename__ = "tokens"

    id = Column(Integer, primary_key=True, index=True)
    token_id = Column(String, unique=True, nullable=False)
    token_name = Column(String, unique=True, nullable=False)
    token_type = Column(String, nullable=False)

class Triggers(Base):
    __tablename__ = "triggers"
    id = Column(Integer, primary_key=True, nullable=False)   
    token_reference = Column(Integer, ForeignKey("tokens.id"), nullable=False) 
    user_agent = Column(String, nullable=True)
    source_ip = Column(String, nullable=True)
    