"""
SENTINEL AI -- Code Scan Worker
Handles Bandit and Semgrep distributed execution.
"""
import asyncio
from typing import List
from backend.workers.base import WorkerBase
from backend.services.scan_control.tool_executor import run_bandit, run_semgrep

class CodeWorker(WorkerBase):
    WORKER_CATEGORY = "code"

    async def execute_scan(self, tool_name: str, target: str, config: dict) -> List[dict]:
        if tool_name == "bandit":
            return await run_bandit(target, config)
        elif tool_name == "semgrep":
            return await run_semgrep(target, config)
        else:
            return []

if __name__ == "__main__":
    worker = CodeWorker()
    asyncio.run(worker.run())
