"""SENTINEL AI — Scan Schemas"""
import json
from pydantic import BaseModel, field_validator
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone


class ScanCreate(BaseModel):
    name: str
    scan_type: str = "full"
    target_id: Optional[str] = None
    target_raw: Optional[str] = None
    tools: List[str] = []
    config: Dict[str, Any] = {}
    schedule_cron: Optional[str] = None


class ScanResponse(BaseModel):
    id: str
    name: str
    scan_type: str = "full"
    status: str = "pending"
    progress: int = 0
    target_raw: Optional[str] = None
    tools_used: list = []
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    error_message: Optional[str] = None
    created_at: datetime = None  # populated by DB; default=None avoids mutable default
    org_id: Optional[str] = None
    security_score: Optional[float] = None
    risk_grade: Optional[str] = None
    input_type: Optional[str] = None

    @field_validator('tools_used', mode='before')
    @classmethod
    def parse_tools_used(cls, v):
        """Handle tools_used stored as JSON string in SQLite."""
        if isinstance(v, str):
            try:
                return json.loads(v)
            except (json.JSONDecodeError, TypeError):
                return []
        if v is None:
            return []
        return v

    class Config:
        from_attributes = True


class ScanListResponse(BaseModel):
    items: List[ScanResponse]
    total: int
    page: int
    per_page: int
