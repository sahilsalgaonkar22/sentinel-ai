from typing import List, Dict, Optional
import asyncio
import json
import logging
from backend.services.scan_control.models import Finding, SeverityLevel, Vulnerability, AttackPath

logger = logging.getLogger(__name__)
from backend.services.ai_intelligence.llm_client import llm_client
from backend.services.ai_intelligence.risk_scoring import risk_scorer
from backend.services.ai_intelligence.deduplication import deduplicator
from backend.common.database import AsyncSessionLocal
from sqlalchemy.future import select

class VorotaAI:
    """Vorota AI Intelligence Layer for finding enrichment and correlation."""
    
    def __init__(self):
        self.llm = llm_client
        self.scorer = risk_scorer
        self.dedup = deduplicator

    async def analyze_finding(self, finding: Finding) -> Dict:
        """Enriches a finding using LLM and advanced risk scoring."""
        
        # 1. Deduplication check
        finding_text = f"{finding.title} {finding.description}"
        duplicates = self.dedup.find_duplicates(finding_text)
        
        if duplicates:
            finding.is_duplicate = True
            finding.duplicate_of = duplicates[0]
        
        # 2. Risk Scoring
        # Assuming asset criticality is medium if not specified
        asset_crit = "medium" 
        ai_risk_score = self.scorer.calculate(
            finding.cvss_score, 
            asset_crit, 
            finding.exploit_available
        )
        finding.ai_risk_score = ai_risk_score

        # 3. LLM Enrichment (False Positive Reduction + Remediation)
        prompt = f"""
        Analyze the following security finding:
        Title: {finding.title}
        Description: {finding.description}
        Severity: {finding.severity}
        Tool: {finding.tool_name}
        
        Determine if this is likely a false positive. 
        Provide a detailed remediation plan.
        Identify potential exploit chains.
        Return results in JSON format.
        """
        
        try:
            llm_response = await self.llm.generate(prompt)
            enrichment = json.loads(llm_response)
            finding.ai_analysis = enrichment
            finding.is_false_positive = enrichment.get("is_false_positive", False)
            finding.remediation = enrichment.get("remediation", finding.remediation)
        except Exception as e:
            logger.error("ai.enrichment_error finding_id=%s error=%s", finding.id, e)
            enrichment = {"error": str(e)}

        # 4. Add to vector DB for future deduplication
        self.dedup.add_finding(finding.id, finding_text)
        
        return {
            "finding_id": finding.id,
            "ai_risk_score": ai_risk_score,
            "is_false_positive": finding.is_false_positive,
            "analysis": enrichment
        }

    async def generate_attack_graph(self, findings: List[Finding]) -> List[Dict]:
        """Correlates findings into potential attack paths using LLM reasoning."""
        if not findings:
            return []
            
        findings_summary = "\n".join([f"- {f.id}: {f.title} ({f.severity})" for f in findings])
        
        prompt = f"""
        Given the following security findings, identify potential attack paths where an attacker could chain these vulnerabilities to compromise the system:
        {findings_summary}
        
        Return a list of attack paths with steps, probability, and impact.
        Return results in JSON format.
        """
        
        try:
            llm_response = await self.llm.generate(prompt)
            paths = json.loads(llm_response)
            return paths
        except Exception as e:
            logger.error("ai.attack_graph_generation_error error=%s", e)
            return []

ai_engine = VorotaAI()
