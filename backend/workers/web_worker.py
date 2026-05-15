"""
SENTINEL AI -- Web Scan Worker
Handles ZAP and Nikto distributed execution.
"""
import asyncio
from typing import List
from backend.workers.base import WorkerBase
from backend.services.scan_control.tool_executor import run_zap, run_nikto, run_http_security

class WebWorker(WorkerBase):
    WORKER_CATEGORY = "web"

    async def execute_scan(self, tool_name: str, target: str, config: dict) -> List[dict]:
        if tool_name == "zap":
            return await run_zap(target, config)
        elif tool_name == "nikto":
            return await run_nikto(target, config)
        elif tool_name == "http_security":
            return await run_http_security(target, config)
        else:
            return []

if __name__ == "__main__":
    worker = WebWorker()
    asyncio.run(worker.run())
