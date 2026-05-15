"""
SENTINEL AI -- Advanced Scan Worker
Handles Pentagi (Docker container) distributed execution.
"""
import asyncio
from typing import List
from backend.workers.base import WorkerBase
from backend.services.scan_control.tool_executor import run_pentagi

class AdvancedWorker(WorkerBase):
    WORKER_CATEGORY = "advanced"

    async def execute_scan(self, tool_name: str, target: str, config: dict) -> List[dict]:
        if tool_name == "pentagi":
            return await run_pentagi(target, config)
        else:
            return []

if __name__ == "__main__":
    worker = AdvancedWorker()
    asyncio.run(worker.run())
