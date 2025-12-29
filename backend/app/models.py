from sqlalchemy import Column, Integer, String, DateTime, Text, BigInteger
from app.database import Base
import datetime

class LogEvent(Base):
    """
    Unified forensic event model.
    Stores normalized log data from all sources.
    """
    __tablename__ = "log_events"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    source = Column(String(50), nullable=False, index=True)  # nginx, php, mysql
    ip = Column(String(45), nullable=False, index=True)  # Supports IPv6
    method = Column(String(10), nullable=True)
    endpoint = Column(String(500), nullable=True, index=True)
    status = Column(Integer, nullable=True)
    response_size = Column(BigInteger, default=0)  # Bytes
    payload = Column(Text, nullable=True)
    raw = Column(Text, nullable=False)  # Original log line
    risk_score = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
