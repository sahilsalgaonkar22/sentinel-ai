"""
SENTINEL AI — API Schemas
Pydantic models for all API request/response contracts.
"""
from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum
from .vulnerability import FindingResponse, VulnerabilityResponse, VulnListResponse
from .scan import ScanResponse, ScanListResponse, ScanCreate
from .auth import Token, UserResponse, LoginRequest, RegisterRequest
from .asset import AssetResponse, AssetListResponse, AssetCreate














# ─── Attack Paths ────────────────────────────────
class AttackPathResponse(BaseModel):
    id: str
    name: str
    description: Optional[str]
    severity: str
    risk_score: float
    chain_steps: list
    entry_point: Optional[str]
    final_impact: Optional[str]
    ai_analysis: Optional[str]
    mitigation_steps: list
    created_at: datetime

    class Config:
        from_attributes = True


# ─── Dashboard ───────────────────────────────────
class DashboardStats(BaseModel):
    risk_index: float
    total_assets: int
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    active_scans: int
    scans_today: int
    system_health: float
    network_throughput: str
    active_threats: int
    recent_findings: List[FindingResponse]
    recent_scans: List[ScanResponse]

class AIInsight(BaseModel):
    id: str
    type: str  # prediction, correlation, recommendation
    title: str
    content: str
    confidence: float
    severity: str
    related_vulns: List[str] = []
    created_at: datetime


# Forward reference resolution
# TokenResponse.model_rebuild()
