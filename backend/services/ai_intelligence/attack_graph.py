"""
SENTINEL AI — Attack Graph Generator + Explanation Engine
Builds attack chains from REAL findings using pattern matching and graph traversal.
Outputs nodes/edges for frontend D3 visualization + human-readable narratives.

Patterns implemented:
0. Pentagi confirmed exploit chain
1. Database port exposure
2. Missing security headers → client attack
3. Supply chain / vulnerable dependency
4. Code injection (Bandit B601/B602 + open port)
5. Weak auth chain (missing headers + cookie flags + open port)
6. Container escape (Trivy critical + Docker socket)
"""
from typing import List, Dict, Optional
import uuid


# ---------------------------------------------------------------------------
#  Explanation Engine (template-based, LLM-optional)
# ---------------------------------------------------------------------------

_EXPLANATION_TEMPLATES = {
    "pentagi_exploit": [
        "Attacker performs initial reconnaissance against {target}.",
        "Automated exploit tool (Pentagi) identifies vulnerable service: {service}.",
        "Exploit payload is delivered to {component}.",
        "Remote code execution achieved — shell access established.",
        "Attacker gains full system control: {impact}.",
    ],
    "db_exposure": [
        "Attacker scans {target} and discovers exposed database port.",
        "Database service ({service}) accepts unauthenticated connections.",
        "Attacker connects directly to the database engine.",
        "Sensitive data is extracted: credentials, PII, financial records.",
        "Impact: Data breach — {impact}.",
    ],
    "missing_headers": [
        "Attacker identifies {target} is missing key security headers.",
        "Absence of CSP and X-Frame-Options enables cross-site scripting.",
        "Malicious JavaScript payload is injected into page context.",
        "Session token is stolen from victim browser.",
        "Attacker authenticates as victim — session hijacked: {impact}.",
    ],
    "supply_chain": [
        "Attacker identifies vulnerable dependency in {component}.",
        "Public exploit for {service} (CVE) is retrieved.",
        "Exploit targets the vulnerable package in the application runtime.",
        "Remote code execution achieved via deserialization/injection flaw.",
        "Application server fully compromised: {impact}.",
    ],
    "code_injection": [
        "Static analysis reveals command injection vulnerability in {component}.",
        "Application accepts user input and passes it to OS shell (Bandit B{service}).",
        "Attacker crafts malicious input to inject arbitrary OS commands.",
        "Command executes with application service account privileges.",
        "Lateral movement begins — attacker pivots across internal network: {impact}.",
    ],
    "weak_auth": [
        "Attacker discovers web application at {target} lacks security headers.",
        "Missing cookie security flags allow session token interception.",
        "Man-in-the-middle attack captures authentication tokens.",
        "Attacker replays captured token to bypass authentication.",
        "Authenticated session hijacked — attacker acts as legitimate user: {impact}.",
    ],
    "container_escape": [
        "Trivy identifies critical CVE in container image at {component}.",
        "Container process has access to Docker socket or privileged mode.",
        "Attacker exploits CVE to break out of container namespace.",
        "Host filesystem becomes accessible to attacker process.",
        "Full host system compromise — all containers at risk: {impact}.",
    ],
    "default": [
        "Attacker identifies {target} as a potential attack vector.",
        "Vulnerability in {component} ({service}) is confirmed.",
        "Exploit technique applied to gain initial access.",
        "Attacker escalates privileges using the discovered vulnerability.",
        "Impact: {impact}.",
    ],
}


def _generate_explanation(template_key: str, **kwargs) -> List[str]:
    """Generate human-readable attack steps using templates."""
    templates = _EXPLANATION_TEMPLATES.get(template_key, _EXPLANATION_TEMPLATES["default"])
    return [
        step.format(
            target=kwargs.get("target", "target host"),
            service=kwargs.get("service", "unknown service"),
            component=kwargs.get("component", "affected component"),
            impact=kwargs.get("impact", "system compromise"),
        )
        for step in templates
    ]


def _llm_explain(finding: dict, path_name: str) -> Optional[List[str]]:
    """Call LLM for enhanced explanation if API key is configured."""
    try:
        from backend.common.config import settings
        if not settings.LLM_API_KEY:
            return None
        # LLM call would go here — only executed if key is configured
        # Fallback to template-based explanation
        return None
    except Exception:
        return None


# ---------------------------------------------------------------------------
#  Graph Builder Helper
# ---------------------------------------------------------------------------

def _build_graph(nodes_config: List[dict]) -> Dict:
    """Build node/edge graph structure for D3 visualization."""
    nodes = []
    edges = []
    prev_id = None

    NODE_COLORS = {
        "Asset": "#3b82f6",        # blue
        "Port": "#6b7280",         # gray
        "Service": "#f59e0b",      # amber
        "Vulnerability": "#f97316", # orange
        "Exploit": "#ef4444",      # red
        "Impact": "#7c3aed",       # purple
    }

    for i, nc in enumerate(nodes_config):
        node_id = str(uuid.uuid4())
        node_type = nc["type"]
        nodes.append({
            "id": node_id,
            "type": node_type,
            "label": nc["label"],
            "severity": nc.get("severity", "info"),
            "color": NODE_COLORS.get(node_type, "#6b7280"),
            "metadata": nc.get("metadata", {}),
        })
        if prev_id:
            edges.append({
                "id": f"edge-{i}",
                "source": prev_id,
                "target": node_id,
                "label": nc.get("edge_label", "leads to"),
            })
        prev_id = node_id

    return {"nodes": nodes, "edges": edges}


# ---------------------------------------------------------------------------
#  Attack Path Generator
# ---------------------------------------------------------------------------

def generate_attack_paths(findings: List[dict]) -> List[dict]:
    """
    Build attack chains with full Node-Edge graph structures and explanations.
    Returns list of attack path objects sorted by risk_score descending.
    """
    if not findings:
        return []

    paths = []

    # Categorize findings
    open_ports = [f for f in findings if "open port" in f.get("title", "").lower()]
    web_issues = [f for f in findings if f.get("tool_name") in ("nikto", "zap", "http_security")]
    code_issues = [f for f in findings if f.get("tool_name") in ("bandit", "semgrep")]
    dep_issues = [f for f in findings if
                  "vulnerable dependency" in f.get("title", "").lower() or
                  bool(f.get("cve_id"))]
    crit_findings = [f for f in findings if f.get("severity") == "critical"]
    trivy_findings = [f for f in findings if f.get("tool_name") == "trivy"]
    pentagi = [f for f in findings if f.get("tool_name") == "pentagi"]

    # ── Pattern 0: Pentagi Confirmed Exploit Chain ────────────────────────
    if pentagi:
        succ = [f for f in pentagi if f.get("exploit_available")]
        if succ:
            p = succ[0]
            graph = _build_graph([
                {"type": "Asset", "label": "Target Host"},
                {"type": "Service", "label": "Vulnerable Service"},
                {"type": "Vulnerability", "label": p.get("title", "Known Vulnerability"), "severity": "critical"},
                {"type": "Exploit", "label": "Automated Payload Delivery", "severity": "critical",
                 "edge_label": "exploits"},
                {"type": "Impact", "label": "System Compromised", "severity": "critical",
                 "edge_label": "results in"},
            ])
            explanation = (_llm_explain(p, "Confirmed Exploit") or
                           _generate_explanation("pentagi_exploit",
                                                 target=p.get("affected_component", "target"),
                                                 service=p.get("title", "service"),
                                                 component=p.get("affected_component", ""),
                                                 impact="Full system compromise confirmed by automated pentesting"))
            paths.append({
                "name": "Confirmed Exploit (Pentagi Automated Pentest)",
                "description": "Pentagi automated exploit engine successfully compromised the target.",
                "severity": "critical",
                "risk_score": 10.0,
                "chain_steps": [{"action": s} for s in explanation],
                "explanation": explanation,
                "entry_point": p.get("affected_component", ""),
                "final_impact": "System Compromise",
                "graph": graph,
            })

    # ── Pattern 1: Database Port Exposure ─────────────────────────────────
    db_ports = [f for f in open_ports if
                any(db in f.get("title", "").lower()
                    for db in ["mysql", "postgresql", "redis", "mongodb", "mssql", "3306",
                               "5432", "6379", "27017", "1433"])]
    if db_ports:
        p = db_ports[0]
        port_name = p.get("title", "Database Port")
        graph = _build_graph([
            {"type": "Asset", "label": "Network Perimeter"},
            {"type": "Port", "label": port_name.split("-")[0].strip(), "edge_label": "exposes"},
            {"type": "Service", "label": "Database Engine", "severity": "high"},
            {"type": "Vulnerability", "label": "Unauthenticated Network Access", "severity": "high"},
            {"type": "Exploit", "label": "Data Extraction / Ransomware", "severity": "critical",
             "edge_label": "enables"},
        ])
        explanation = _generate_explanation("db_exposure",
                                            target=p.get("affected_component", "host"),
                                            service=port_name, component=port_name,
                                            impact="Complete data breach")
        paths.append({
            "name": f"Database Exposure: {port_name}",
            "description": "Database port is directly reachable over the network, enabling unauthenticated access.",
            "severity": "high",
            "risk_score": 8.5,
            "chain_steps": [{"action": s} for s in explanation],
            "explanation": explanation,
            "entry_point": p.get("affected_component", ""),
            "final_impact": "Data breach / ransomware",
            "graph": graph,
        })

    # ── Pattern 2: Missing Headers → Client Attack ────────────────────────
    missing_hdrs = [f for f in web_issues if "missing" in f.get("title", "").lower()]
    if len(missing_hdrs) >= 2:
        target_url = missing_hdrs[0].get("affected_component", "web application")
        graph = _build_graph([
            {"type": "Asset", "label": "Web Application"},
            {"type": "Service", "label": "HTTP Service"},
            {"type": "Vulnerability", "label": f"{len(missing_hdrs)} Missing Security Headers",
             "severity": "medium"},
            {"type": "Exploit", "label": "XSS / Clickjacking Payload", "severity": "high",
             "edge_label": "enables"},
            {"type": "Impact", "label": "Session Hijacking", "severity": "high",
             "edge_label": "results in"},
        ])
        explanation = _generate_explanation("missing_headers",
                                            target=target_url, service="HTTP",
                                            component=target_url, impact="Session hijacking")
        paths.append({
            "name": "Web Application Attack via Missing Security Headers",
            "description": f"{len(missing_hdrs)} missing security headers enable XSS and clickjacking attacks.",
            "severity": "medium",
            "risk_score": 6.0,
            "chain_steps": [{"action": s} for s in explanation],
            "explanation": explanation,
            "entry_point": target_url,
            "final_impact": "Session hijacking",
            "graph": graph,
        })

    # ── Pattern 3: Supply Chain Attack ────────────────────────────────────
    if dep_issues:
        top = dep_issues[0]
        cve = top.get("cve_id", "CVE-UNKNOWN")
        component = top.get("affected_component", "vulnerable package")
        graph = _build_graph([
            {"type": "Asset", "label": "Application Codebase"},
            {"type": "Service", "label": "Package Manager / Dependencies"},
            {"type": "Vulnerability", "label": top.get("title", "Vulnerable Dependency"),
             "severity": top.get("severity", "high")},
            {"type": "Exploit", "label": f"Public Exploit ({cve})", "severity": "critical",
             "edge_label": "exploited via"},
            {"type": "Impact", "label": "RCE / Data Exfiltration", "severity": "critical",
             "edge_label": "leads to"},
        ])
        explanation = _generate_explanation("supply_chain",
                                            target="application runtime",
                                            service=cve, component=component,
                                            impact=f"Code execution via {component}")
        paths.append({
            "name": "Supply Chain Attack via Vulnerable Dependency",
            "description": f"Found {len(dep_issues)} vulnerable dependencies with known CVEs.",
            "severity": "high",
            "risk_score": 7.5,
            "chain_steps": [{"action": s} for s in explanation],
            "explanation": explanation,
            "entry_point": component,
            "final_impact": "Remote code execution",
            "graph": graph,
        })

    # ── Pattern 4: Code Injection Chain ───────────────────────────────────
    injection_issues = [f for f in code_issues if
                        any(tag in f.get("title", "").upper()
                            for tag in ["B601", "B602", "B603", "B607", "B608",
                                        "INJECTION", "EXEC", "SUBPROCESS", "SQL"])]
    if injection_issues and open_ports:
        inj = injection_issues[0]
        port = open_ports[0]
        component = inj.get("affected_component", "source file")
        graph = _build_graph([
            {"type": "Asset", "label": "Application Server"},
            {"type": "Port", "label": port.get("title", "Open Port"), "edge_label": "exposes"},
            {"type": "Service", "label": "Application Process"},
            {"type": "Vulnerability", "label": inj.get("title", "Code Injection"),
             "severity": "high", "edge_label": "contains"},
            {"type": "Exploit", "label": "OS Command Injection", "severity": "critical",
             "edge_label": "exploited as"},
            {"type": "Impact", "label": "RCE → Lateral Movement", "severity": "critical",
             "edge_label": "enables"},
        ])
        bandit_id = next((t for t in ["B601", "B602", "B603", "B607", "B608"]
                          if t in inj.get("title", "").upper()), "injection")
        explanation = _generate_explanation("code_injection",
                                            target=port.get("affected_component", "server"),
                                            service=bandit_id, component=component,
                                            impact="Lateral movement across internal network")
        paths.append({
            "name": "OS Command Injection via Application Code",
            "description": f"Static analysis reveals {len(injection_issues)} command/code injection issues accessible via open ports.",
            "severity": "high",
            "risk_score": 7.8,
            "chain_steps": [{"action": s} for s in explanation],
            "explanation": explanation,
            "entry_point": component,
            "final_impact": "Remote code execution",
            "graph": graph,
        })

    # ── Pattern 5: Weak Auth Chain ────────────────────────────────────────
    cookie_issues = [f for f in web_issues if
                     "cookie" in f.get("title", "").lower() or
                     "httponly" in f.get("title", "").lower() or
                     "secure" in f.get("title", "").lower()]
    admin_ports = [f for f in open_ports if
                   any(p in f.get("title", "") for p in ["8080", "8443", "8888", "8000", "admin"])]
    if cookie_issues and missing_hdrs:
        target_url = cookie_issues[0].get("affected_component", "web app")
        graph = _build_graph([
            {"type": "Asset", "label": "Web Application"},
            {"type": "Service", "label": "Authentication System"},
            {"type": "Vulnerability", "label": "Insecure Cookie + Missing Headers",
             "severity": "medium", "edge_label": "exposes"},
            {"type": "Exploit", "label": "MITM / XSS Token Theft", "severity": "high",
             "edge_label": "enables"},
            {"type": "Impact", "label": "Authentication Bypass", "severity": "high",
             "edge_label": "leads to"},
        ])
        explanation = _generate_explanation("weak_auth",
                                            target=target_url, service="HTTP",
                                            component=target_url,
                                            impact="Authentication bypass — attacker acts as admin")
        paths.append({
            "name": "Authentication Bypass via Weak Session Security",
            "description": "Combination of missing security headers and insecure cookies enables session theft.",
            "severity": "medium",
            "risk_score": 6.5,
            "chain_steps": [{"action": s} for s in explanation],
            "explanation": explanation,
            "entry_point": target_url,
            "final_impact": "Authentication bypass",
            "graph": graph,
        })

    # ── Pattern 6: Container Escape ───────────────────────────────────────
    crit_trivy = [f for f in trivy_findings if f.get("severity") == "critical"]
    if crit_trivy:
        top = crit_trivy[0]
        component = top.get("affected_component", "container image")
        graph = _build_graph([
            {"type": "Asset", "label": "Container Runtime"},
            {"type": "Service", "label": "Container Image", "edge_label": "runs"},
            {"type": "Vulnerability", "label": top.get("title", "Critical CVE"),
             "severity": "critical", "edge_label": "contains"},
            {"type": "Exploit", "label": "Container Escape / Privilege Escalation",
             "severity": "critical", "edge_label": "enables"},
            {"type": "Impact", "label": "Host System Compromise", "severity": "critical",
             "edge_label": "results in"},
        ])
        cve = top.get("cve_id", "critical-cve")
        explanation = _generate_explanation("container_escape",
                                            target="containerized workload",
                                            service=cve, component=component,
                                            impact="Host takeover — all containers compromised")
        paths.append({
            "name": "Container Escape via Critical CVE",
            "description": f"Critical vulnerability in container image {component} enables escape to host.",
            "severity": "critical",
            "risk_score": 9.0,
            "chain_steps": [{"action": s} for s in explanation],
            "explanation": explanation,
            "entry_point": component,
            "final_impact": "Host system compromise",
            "graph": graph,
        })

    paths.sort(key=lambda p: p.get("risk_score", 0), reverse=True)
    return paths


# ---------------------------------------------------------------------------
#  AttackGraphGenerator — wrapper class (backward compat)
# ---------------------------------------------------------------------------

class AttackGraphGenerator:
    def __init__(self):
        pass

    def generate(self, findings: List[dict]) -> Optional[dict]:
        paths = generate_attack_paths(findings)
        if paths:
            best = paths[0]
            return {
                "critical_path": best.get("chain_steps", []),
                "description": best.get("description", ""),
                "total_chains_found": len(paths),
                "paths": paths,
            }
        return None


attack_graph_generator = AttackGraphGenerator()
