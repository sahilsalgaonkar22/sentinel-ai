import asyncio
import sys
import os
os.environ['DATABASE_URL'] = 'sqlite+aiosqlite:///./sentinel_dev.db'
sys.path.insert(0, '.')

from backend.services.scan_control.tool_executor import run_nmap, run_http_security
import traceback

async def main():
    print("=== PHASE 2: REAL TOOL EXECUTION ===", flush=True)

    print("\n--- Test 1: port probe on 127.0.0.1 ---", flush=True)
    try:
        findings = await run_nmap('127.0.0.1', {})
        print(f"Findings count: {len(findings)}", flush=True)
        for f in findings[:5]:
            print(f"  [{f['severity']}] {f['title']} | tool={f['tool_name']} | component={f['affected_component']}", flush=True)
    except Exception as e:
        print(f"  ERROR: {e}", flush=True)
        traceback.print_exc()

    print("\n--- Test 2: HTTP header scan on example.com ---", flush=True)
    try:
        findings2 = await run_http_security('example.com', {})
        print(f"Findings count: {len(findings2)}", flush=True)
        for f in findings2[:5]:
            print(f"  [{f['severity']}] {f['title']}", flush=True)
    except Exception as e:
        print(f"  ERROR: {e}", flush=True)
        traceback.print_exc()

    print("\n--- Test 3: HTTP scan on httpbin.org ---", flush=True)
    try:
        findings3 = await run_http_security('httpbin.org', {})
        print(f"Findings count: {len(findings3)}", flush=True)
        for f in findings3[:5]:
            print(f"  [{f['severity']}] {f['title']}", flush=True)
    except Exception as e:
        print(f"  ERROR: {e}", flush=True)
        traceback.print_exc()

    print("\n--- Test 4: Bandit on local backend code ---", flush=True)
    try:
        from backend.services.scan_control.tool_executor import run_bandit
        findings4 = await run_bandit('.', {})
        print(f"Findings count: {len(findings4)}", flush=True)
        for f in findings4[:3]:
            print(f"  [{f['severity']}] {f['title']}", flush=True)
    except Exception as e:
        print(f"  ERROR: {e}", flush=True)
        traceback.print_exc()

asyncio.run(main())
print("DONE", flush=True)
