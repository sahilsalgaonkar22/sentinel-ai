"""Submit scan, poll progress, get findings, generate report."""
import httpx, json, time

def main():
    r = httpx.post('http://localhost:8000/auth/login', data={'username':'admin@sentinel.ai','password':'admin123'})
    token = r.json()['access_token']
    headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}
    
    # Submit scan
    print("=" * 60)
    print("SUBMITTING SCAN: scanme.nmap.org")
    print("=" * 60)
    scan_data = {
        'name': 'Full Security Audit - scanme.nmap.org',
        'target_raw': 'http://scanme.nmap.org',
        'scan_type': 'full'
    }
    r2 = httpx.post('http://localhost:8000/scans/', json=scan_data, headers=headers, timeout=30, follow_redirects=True)
    scan = r2.json()
    scan_id = scan['id']
    print(f"Scan ID: {scan_id}")
    print(f"Status: {scan['status']}")

    # Poll progress
    print("\n" + "=" * 60)
    print("SCAN PROGRESS")
    print("=" * 60)
    for i in range(60):
        time.sleep(5)
        r3 = httpx.get(f'http://localhost:8000/scans/{scan_id}', headers=headers, timeout=30)
        s = r3.json()
        status = s.get('status', '?')
        progress = s.get('progress', 0)
        findings = s.get('total_findings', 0)
        tools = s.get('tools_used', [])
        print(f"[{(i+1)*5:3d}s] status={status} progress={progress}% findings={findings} tools={tools}", flush=True)
        if status in ('completed', 'failed'):
            break
    
    # Final scan result
    print("\n" + "=" * 60)
    print("FINAL SCAN RESULT")
    print("=" * 60)
    r4 = httpx.get(f'http://localhost:8000/scans/{scan_id}', headers=headers, timeout=30)
    print(json.dumps(r4.json(), indent=2, default=str)[:1500])

    # Get findings
    print("\n" + "=" * 60)
    print("VULNERABILITY FINDINGS")
    print("=" * 60)
    r5 = httpx.get(f'http://localhost:8000/scans/{scan_id}/findings', headers=headers, timeout=30)
    data = r5.json()
    findings_list = data.get('findings', data) if isinstance(data, dict) else data
    if isinstance(findings_list, list):
        for i, f in enumerate(findings_list):
            if isinstance(f, dict):
                print(f"\n--- Finding {i+1} ---")
                print(f"  Title:    {f.get('title','?')}")
                print(f"  Severity: {f.get('severity','?')}")
                print(f"  Tool:     {f.get('tool_name','?')}")
                print(f"  CVSS:     {f.get('cvss_score','?')}")
                print(f"  CWE:      {f.get('cwe_id','?')}")
                desc = f.get('description','')[:150]
                print(f"  Desc:     {desc}")
    else:
        print(json.dumps(data, indent=2, default=str)[:3000])

    # Generate report
    print("\n" + "=" * 60)
    print("PDF REPORT GENERATION")
    print("=" * 60)
    try:
        report_data = {'scan_id': scan_id, 'format': 'pdf'}
        r6 = httpx.post('http://localhost:8000/reporting/generate', json=report_data, headers=headers, timeout=60, follow_redirects=True)
        print(f"Report Status: {r6.status_code}")
        print(json.dumps(r6.json(), indent=2, default=str)[:500])
    except Exception as e:
        print(f"Error: {e}")

    print("\n" + "=" * 60)
    print("SCAN ID FOR BROWSER:", scan_id)
    print("=" * 60)

if __name__ == '__main__':
    main()
