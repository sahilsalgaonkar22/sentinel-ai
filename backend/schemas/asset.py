
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime

# ─── Assets ──────────────────────────────────────
class AssetCreate(BaseModel):
    name: str
    asset_type: str
    target: str
    environment: str = "production"
    criticality: str = "medium"
    tags: Dict[str, Any] = {}
    location: Optional[str] = None

class AssetResponse(BaseModel):
    id: str
    name: str
    asset_type: str
    target: str
    environment: str
    criticality: str
    is_active: bool
    risk_score: float
    last_scan_at: Optional[datetime]
    location: Optional[str]
    tags: Dict[str, Any]
    created_at: datetime

    class Config:
        from_attributes = True

class AssetListResponse(BaseModel):
    items: List[AssetResponse]
    total: int
    page: int
    per_page: int
