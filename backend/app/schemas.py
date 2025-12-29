from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime

# Unified Event Model (matches database model)
class UnifiedEvent(BaseModel):
    timestamp: datetime
    source: str
    ip: str
    method: Optional[str] = None
    endpoint: Optional[str] = None
    status: Optional[int] = None
    response_size: int = 0
    payload: Optional[str] = None
    raw: str
    
    class Config:
        from_attributes = True

# API Request/Response Models
class UploadResponse(BaseModel):
    filename: str
    log_type: str
    events_ingested: int
    message: str

class SystemStats(BaseModel):
    total_events: int
    unique_ips: int
    unique_endpoints: int
    total_data_volume: int
    analysis_timestamp: str

class EndpointAnalysis(BaseModel):
    endpoint: str
    total_hits: int
    unique_ips: int
    total_data_volume: int
    avg_response_size: int
    risk_score: int
    risk_level: str

class IPAnalysis(BaseModel):
    ip: str
    total_requests: int
    endpoints_accessed: List[str]
    requests_per_minute: float
    automation_confidence: float
    risk_score: int
