
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import datetime

class ScanRequested(BaseModel):
    scan_id: str
    name: str
    scan_type: str
    target_raw: str
    tools: List[str]
    config: Dict[str, Any]

class ScanStarted(BaseModel):
    scan_id: str
    worker_id: str
    started_at: datetime

class ScanProgress(BaseModel):
    scan_id: str
    progress: int
    status_message: str

class ScanCompleted(BaseModel):
    scan_id: str
    completed_at: datetime
    raw_results_path: str

class FindingRaw(BaseModel):
    scan_id: str
    finding_id: str
    title: str
    description: str
    severity: str
    tool_name: str
    raw_finding: Dict[str, Any]

class FindingProcessed(BaseModel):
    scan_id: str
    finding_id: str
    title: str
    description: str
    severity: str
    cvss_score: float
    cve_id: Optional[str]
    cwe_id: Optional[str]
    remediation: str
    is_false_positive: bool
    ai_risk_score: float
    exploit_available: bool

class AlertCritical(BaseModel):
    finding_id: str
    title: str
    severity: str
    cvss_score: float
    affected_asset: str
