"""
SENTINEL AI -- Container Scan Worker
Handles Trivy distributed execution.
"""
import asyncio
from typing import List
from backend.workers.base import WorkerBase
from backend.services.scan_control.tool_executor import run_trivy

class ContainerWorker(WorkerBase):
    WORKER_CATEGORY = "container"

    async def execute_scan(self, tool_name: str, target: str, config: dict) -> List[dict]:
        if tool_name == "trivy":
            return await run_trivy(target, config)
        else:
            return []

if __name__ == "__main__":
    worker = ContainerWorker()
    asyncio.run(worker.run())
