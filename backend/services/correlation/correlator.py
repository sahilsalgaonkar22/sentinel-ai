
from typing import List, Dict

class Correlator:
    def __init__(self):
        self.findings_cache = {}

    def correlate(self, new_finding: Dict) -> List[Dict]:
        """Correlate a new finding with existing findings."""
        org_id = new_finding.get('org_id', 'default')
        if org_id not in self.findings_cache:
            self.findings_cache[org_id] = []

        correlated_findings = []
        for existing_finding in self.findings_cache[org_id]:
            # Simple correlation logic: if two findings affect the same asset, they are correlated.
            # A real implementation would be much more sophisticated.
            if new_finding.get('affected_component') == existing_finding.get('affected_component'):
                correlated_findings.append(existing_finding)
        
        self.findings_cache[org_id].append(new_finding)
        return correlated_findings

correlator = Correlator()
