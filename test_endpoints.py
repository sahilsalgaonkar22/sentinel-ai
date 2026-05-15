import asyncio, json
from backend.common.database import get_db
from backend.gateway.routes.dashboard import get_analytics, get_ai_insights
from backend.gateway.routes.vulnerabilities import list_vulnerabilities

async def test():
    user = {"org_id": "org-default-001", "role": "admin", "sub": "admin@sentinel.ai"}

    async for db in get_db(None):
        analytics = await get_analytics(db=db, user=user)
        print("=== /dashboard/analytics ===")
        vuln_sev = analytics.get("vuln_by_severity", [])
        print("vuln_by_severity:", json.dumps(vuln_sev))
        print("avg_risk_score:", analytics.get("avg_risk_score"))
        print("total_scans:", analytics.get("total_scans_30d"))
        ap = analytics.get("attack_probability", [])
        print("attack_probability:", json.dumps(ap))
        print("ai_prediction_insight:", analytics.get("ai_prediction_insight", "")[:200])
        break

    async for db in get_db(None):
        ai = await get_ai_insights(db=db, user=user)
        print("\n=== /dashboard/ai-insights ===")
        print("has_data:", ai.get("has_data"))
        if ai.get("summary"):
            print("summary:", ai["summary"][:200])
        print("exploit_chain items:", len(ai.get("exploit_chain", [])))
        print("remediation_plan items:", len(ai.get("remediation_plan", [])))
        break

asyncio.run(test())
