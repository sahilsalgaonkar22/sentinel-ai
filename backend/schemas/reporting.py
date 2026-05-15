
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

class ReportCreate(BaseModel):
    name: str
    report_type: str
    format: str
    scan_ids: List[str]
    filters: Optional[dict] = None

class ReportResponse(BaseModel):
    id: str
    name: str
    report_type: str
    format: str
    status: str
    download_url: Optional[str] = None
    created_at: datetime
    
    class Config:
        from_attributes = True
