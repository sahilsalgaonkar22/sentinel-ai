"""
SENTINEL AI -- Unified Scan Worker
Subscribes to ALL scan topic categories (network, web, code, container, advanced)
so a single worker container handles every scan type.

This replaces the old single-category approach where the Dockerfile CMD
hardcoded `network_worker.py` and other scan types were silently dropped.
"""
import asyncio
import json
import os
import logging
from typing import List

from backend.workers.base import WorkerBase
from backend.services.scan_control.tool_executor import (
    run_nmap, run_masscan,
    run_zap, run_nikto, run_http_security,
    run_bandit, run_semgrep,
    run_trivy,
    run_pentagi,
    run_nuclei, run_subfinder, run_httpx_probe, run_gitleaks,
)

logger = logging.getLogger(__name__)


# Map every tool name to its async runner function
TOOL_DISPATCH = {
    # Network
    "nmap": run_nmap,
    "masscan": run_masscan,
    # Web
    "zap": run_zap,
    "nikto": run_nikto,
    "http_security": run_http_security,
    "nuclei": run_nuclei,
    "httpx": run_httpx_probe,
    # Recon
    "subfinder": run_subfinder,
    # Code / SAST
    "bandit": run_bandit,
    "semgrep": run_semgrep,
    "gitleaks": run_gitleaks,
    # Container
    "trivy": run_trivy,
    # Advanced
    "pentagi": run_pentagi,
}


class UnifiedWorker(WorkerBase):
    """
    Subscribes to all scan job topics and dispatches to the correct tool runner.
    """
    WORKER_CATEGORY = "unified"

    # Override: subscribe to ALL topics instead of just one
    ALL_TOPICS = [
        "scan.jobs.network",
        "scan.jobs.web",
        "scan.jobs.code",
        "scan.jobs.container",
        "scan.jobs.advanced",
    ]

    def _init_kafka(self):
        """
        Override base _init_kafka to subscribe to ALL scan topics
        and skip category-specific tool validation (we validate all).
        """
        from confluent_kafka import Consumer, Producer
        from backend.services.kafka.manager import kafka_manager
        sasl = kafka_manager._sasl_conf()

        self.consumer = Consumer({
            "bootstrap.servers": self.bootstrap_servers,
            "group.id": f"{self.GROUP_ID}-unified",
            "auto.offset.reset": "earliest",
            "enable.auto.commit": False,
            "session.timeout.ms": 30000,
            "max.poll.interval.ms": 600000,
            **sasl,
        })
        self.consumer.subscribe(self.ALL_TOPICS)

        self.producer = Producer({
            "bootstrap.servers": self.bootstrap_servers,
            "client.id": "sentinel-worker-unified",
            "message.send.max.retries": 5,
            "retry.backoff.ms": 1000,
            **sasl,
        })

        logger.info(
            "worker.kafka_ready category=unified topics=%s",
            self.ALL_TOPICS
        )

    async def execute_scan(self, tool_name: str, target: str, config: dict) -> List[dict]:
        runner = TOOL_DISPATCH.get(tool_name)
        if not runner:
            logger.warning("worker.unknown_tool tool=%s target=%s", tool_name, target)
            return []

        logger.info("worker.executing tool=%s target=%s", tool_name, target)
        return await runner(target, config)


if __name__ == "__main__":
    worker = UnifiedWorker()
    asyncio.run(worker.run())
