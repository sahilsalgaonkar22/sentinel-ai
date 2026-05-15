import asyncio
import shutil
import logging

logger = logging.getLogger(__name__)


async def run_nmap_scan(target: str):
    nmap_path = shutil.which("nmap")

    if not nmap_path:
        logger.error("Nmap not found")
        return {"error": "nmap_not_found"}

    cmd = [
        nmap_path,
        "-sV",
        "-oX", "-",   # XML output (machine readable)
        target
    ]

    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=60
            )
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            logger.error("Nmap scan timed out")
            return {"error": "timeout"}

        if process.returncode != 0:
            logger.error(f"Nmap error: {stderr.decode()}")
            return {"error": stderr.decode()}

        return {
            "status": "completed",
            "raw_xml": stdout.decode()
        }

    except Exception as e:
        logger.error(f"Nmap execution failed: {e}")
        return {"error": str(e)}