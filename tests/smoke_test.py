
import httpx
import asyncio
import json
import uuid
from datetime import datetime
import websockets

BASE_URL = "http://localhost:8000"
WS_URL = "ws://localhost:8000/ws/neural-stream"

async def smoke_test():
    print("🚀 Starting SENTINEL AI Smoke Test...")
    
    async with httpx.AsyncClient(base_url=BASE_URL, timeout=30.0) as client:
        # 1. Register User
        print("\n1️⃣ Registering User...")
        user_email = f"tester_{uuid.uuid4().hex[:6]}@sentinel.ai"
        reg_resp = await client.post("/auth/register", json={
            "email": user_email,
            "username": f"tester_{uuid.uuid4().hex[:6]}",
            "password": "SecurePassword123!",
            "full_name": "Smoke Tester",
            "org_name": "TestOrg"
        })
        if reg_resp.status_code != 201:
            print(f"❌ Registration failed: {reg_resp.text}")
            return
        
        auth_data = reg_resp.json()
        token = auth_data["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        print(f"✅ User registered: {user_email}")

        # 2. Create Asset
        print("\n2️⃣ Creating Asset...")
        asset_resp = await client.post("/assets", headers=headers, json={
            "name": "Production Web Server",
            "asset_type": "web_server",
            "target": "127.0.0.1",
            "environment": "production",
            "criticality": "high",
            "tags": {"app": "gateway", "tier": "frontend"}
        })
        if asset_resp.status_code != 201:
            print(f"❌ Asset creation failed: {asset_resp.text}")
            return
        
        asset = asset_resp.json()
        asset_id = asset["id"]
        print(f"✅ Asset created: {asset_id}")

        # 3. Connect WebSocket for Real-time Updates
        client_id = f"test-client-{uuid.uuid4().hex[:6]}"
        ws_uri = f"{WS_URL}/{client_id}"
        
        print(f"\n3️⃣ Connecting to WebSocket: {ws_uri}")
        async with websockets.connect(ws_uri) as websocket:
            # 4. Initiate Scan
            print("\n4️⃣ Initiating Scan...")
            scan_resp = await client.post("/scans", headers=headers, json={
                "name": "Full Security Audit",
                "scan_type": "full",
                "target_id": asset_id,
                "target_raw": "127.0.0.1",
                "tools": ["nmap", "zap"],
                "config": {"ports": "80,443,8080", "intensity": "high"}
            })
            if scan_resp.status_code != 202:
                print(f"❌ Scan initiation failed: {scan_resp.text}")
                return
            
            scan = scan_resp.json()
            scan_id = scan["id"]
            print(f"✅ Scan initiated: {scan_id}")

            # 5. Subscribe to Scan via WS
            await websocket.send(json.dumps({
                "type": "subscribe",
                "scan_id": scan_id
            }))
            print(f"📡 Subscribed to scan updates for {scan_id}")

            # 6. Listen for real-time events (Progress, Results, AI Processing)
            print("\n5️⃣ Monitoring Real-time Stream...")
            try:
                # Wait for progress and results
                async for message in websocket:
                    event = json.loads(message)
                    event_type = event.get("type")
                    
                    if event_type == "scan_update":
                        progress = event.get("progress", 0)
                        status = event.get("status_message", "In Progress")
                        print(f"📈 [SCAN PROGRESS] {progress}% - {status}")
                        if progress >= 100:
                            print("✅ Scan Completed!")
                            break
                    
                    elif event_type == "new_finding":
                        print(f"🚨 [NEW FINDING] {event.get('title')} (Severity: {event.get('severity')})")
                        print(f"🤖 [AI RISK SCORE] {event.get('risk_score')}")
                    
                    elif event_type == "threat_alert":
                        print(f"🔥 [CRITICAL ALERT] {event.get('title')}")

            except Exception as e:
                print(f"⚠️ WebSocket stream ended: {e}")

        # 7. Verify Final Results
        print("\n6️⃣ Verifying Final Results...")
        vuln_resp = await client.get("/vulnerabilities", headers=headers)
        if vuln_resp.status_code == 200:
            vulns = vuln_resp.json()["items"]
            print(f"✅ Found {len(vulns)} processed vulnerabilities in database.")
            for v in vulns[:3]:
                print(f"   - {v['title']} (Score: {v['risk_score']})")

    print("\n🎉 SENTINEL AI Smoke Test Completed Successfully!")

if __name__ == "__main__":
    asyncio.run(smoke_test())
