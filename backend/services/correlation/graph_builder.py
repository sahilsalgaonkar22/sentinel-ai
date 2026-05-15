
from typing import List, Dict
from datetime import datetime, timezone
import uuid

class GraphBuilder:
    def build(self, correlated_findings: List[Dict]) -> Dict:
        """Build an attack graph from a list of correlated findings."""
        if not correlated_findings or len(correlated_findings) < 2:
            return None

        path_id = f"AP-{uuid.uuid4()}"
        name = f"Attack Path involving {len(correlated_findings)} vulnerabilities"
        
        nodes = []
        for i, finding in enumerate(correlated_findings):
            node_type = "intermediate"
            if i == 0:
                node_type = "entry"
            elif i == len(correlated_findings) - 1:
                node_type = "exit"
            
            nodes.append({
                "id": finding['finding_id'],
                "title": finding['title'],
                "type": node_type
            })

        return {
            "path_id": path_id,
            "name": name,
            "severity": "high",  # This would be calculated based on the findings
            "risk_score": 8.5, # This would be calculated
            "nodes": nodes,
            "impact": "Potential for lateral movement and privilege escalation.",
            "remediation": "Address the entry point vulnerability to break the chain.",
            "created_at": datetime.now(timezone.utc).isoformat()
        }

graph_builder = GraphBuilder()
