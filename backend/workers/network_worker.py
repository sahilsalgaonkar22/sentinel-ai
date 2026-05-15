"""
SENTINEL AI -- Network Scan Worker
Handles Nmap and Masscan distributed execution.
"""
import asyncio
from typing import List
from backend.workers.base import WorkerBase
from backend.services.scan_control.tool_executor import run_nmap, run_masscan

class NetworkWorker(WorkerBase):
    WORKER_CATEGORY = "network"

    async def execute_scan(self, tool_name: str, target: str, config: dict) -> List[dict]:
        if tool_name == "nmap":
            return await run_nmap(target, config)
        elif tool_name == "masscan":
            return await run_masscan(target, config)
        else:
            return []

if __name__ == "__main__":
    worker = NetworkWorker()
    asyncio.run(worker.run())
