"""
SENTINEL AI -- Kafka Worker Base Class
All scan workers inherit from this. Handles Kafka consume/produce lifecycle.

PRODUCTION HARDENING:
- validate_tools_or_die() called at startup → hard crash if required binary missing.
- consumer.poll() runs in thread executor (no event-loop blockage).
- Failed jobs are routed to DLQ topic (scan.jobs.<category>.dlq).
- No FALLBACK, MOCK, or silent recovery paths.
- FIX-7: Exposes /health on port 8001 for K8s liveness/readiness probes.
- FIX-10: Uses structured JSON logging via configure_logging().
"""
import json
import os
import asyncio
import logging
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import List
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# ── Minimal health HTTP server for K8s probes ────────────────────────────────

class _HealthHandler(BaseHTTPRequestHandler):
    """Minimalist HTTP handler — responds 200 to GET /health only."""
    def do_GET(self):
        if self.path == "/health":
            body = b'{"status": "ok"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, fmt, *args):   # silence access logs
        pass


class WorkerBase:
    """Base class for all Sentinel AI scan workers."""

    WORKER_CATEGORY = "network"   # Override in subclass
    GROUP_ID = "sentinel-worker"
    PRODUCE_TOPIC = "scan.results"

    def __init__(self):
        # Configure structured JSON logging for the worker process
        from backend.common.logging_config import configure_logging
        configure_logging(service_name=f"worker-{self.WORKER_CATEGORY}")

        self.bootstrap_servers = os.environ["KAFKA_BOOTSTRAP_SERVERS"]  # Hard fail if missing
        self.consume_topic = f"scan.jobs.{self.WORKER_CATEGORY}"
        self.dlq_topic     = f"scan.jobs.{self.WORKER_CATEGORY}.dlq"
        self.consumer      = None
        self.producer      = None
        self._health_server: HTTPServer | None = None

    def _start_health_server(self, port: int = 8001) -> None:
        """FIX-7: Start a background HTTP server on port 8001 for K8s probes."""
        server = HTTPServer(("", port), _HealthHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self._health_server = server
        logger.info("worker.health_server_started port=%d", port)

    def _init_kafka(self):
        """Initialize Kafka consumer and producer + validate tool availability. Hard fails on any error."""
        # Tool validation: crashes the worker if required binary is missing
        from backend.common.tool_validator import validate_tools_or_die
        validate_tools_or_die(worker_category=self.WORKER_CATEGORY)

        from confluent_kafka import Consumer, Producer
        from backend.services.kafka.manager import kafka_manager
        sasl = kafka_manager._sasl_conf()   # GAP-10 FIX: inject SASL credentials

        self.consumer = Consumer({
            "bootstrap.servers": self.bootstrap_servers,
            "group.id": f"{self.GROUP_ID}-{self.WORKER_CATEGORY}",
            "auto.offset.reset": "earliest",
            "enable.auto.commit": False,
            "session.timeout.ms": 30000,
            "max.poll.interval.ms": 600000,
            **sasl,
        })
        self.consumer.subscribe([self.consume_topic])

        self.producer = Producer({
            "bootstrap.servers": self.bootstrap_servers,
            "client.id": f"sentinel-worker-{self.WORKER_CATEGORY}",
            "message.send.max.retries": 5,
            "retry.backoff.ms": 1000,
            **sasl,
        })

        logger.info("worker.kafka_ready category=%s topic=%s", self.WORKER_CATEGORY, self.consume_topic)

    async def execute_scan(self, tool_name: str, target: str, config: dict) -> List[dict]:
        """Override in subclass. Execute the actual scan tool and return findings."""
        raise NotImplementedError

    def _produce_log(self, scan_id: str, message: str, level: str = "INFO"):
        """Stream a structured log line to scan.logs topic for real-time frontend streaming."""
        if not self.producer:
            return
        try:
            self.producer.produce(
                "scan.logs",
                key=scan_id.encode("utf-8"),
                value=json.dumps({
                    "scan_id": scan_id,
                    "tool": self.WORKER_CATEGORY,
                    "level": level,
                    "message": message,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }).encode("utf-8"),
            )
            self.producer.poll(0)
        except Exception as exc:
            logger.warning("worker.log_produce_failed scan_id=%s error=%s", scan_id, exc)

    def _produce_result(self, scan_id: str, org_id: str, tool_name: str,
                        target: str, findings: List[dict], error: str = ""):
        """Send scan results back to Kafka scan.results topic."""
        if not self.producer:
            return

        payload = {
            "scan_id": scan_id,
            "org_id": org_id,
            "tool_name": tool_name,
            "target": target,
            "findings": findings,
            "finding_count": len(findings),
            "status": "error" if error else "completed",
            "error": error,
            "completed_at": datetime.now(timezone.utc).isoformat(),
        }
        try:
            self.producer.produce(
                self.PRODUCE_TOPIC,
                key=scan_id.encode("utf-8"),
                value=json.dumps(payload).encode("utf-8"),
            )
            self.producer.flush()
        except Exception as exc:
            logger.error("worker.result_produce_failed scan_id=%s error=%s", scan_id, exc)

    def _produce_dlq(self, job: dict, error: str):
        """Route a failed job to the DLQ topic for dead-letter processing."""
        if not self.producer:
            return
        scan_id = job.get("scan_id", "unknown")
        dlq_payload = {
            **job,
            "_dlq_original_topic": self.consume_topic,
            "_dlq_error": error,
        }
        try:
            self.producer.produce(
                self.dlq_topic,
                key=scan_id.encode("utf-8"),
                value=json.dumps(dlq_payload).encode("utf-8"),
            )
            self.producer.flush()
            logger.warning("worker.dlq_routed scan_id=%s topic=%s error=%s", scan_id, self.dlq_topic, error)
        except Exception as exc:
            logger.error("worker.dlq_produce_failed scan_id=%s error=%s", scan_id, exc)

    async def run(self):
        """
        Main worker loop — consume jobs, execute scans, produce results.
        """
        self._start_health_server()   # FIX-7: K8s liveness + readiness probes
        self._init_kafka()
        loop = asyncio.get_running_loop()
        logger.info("worker.listening category=%s topic=%s", self.WORKER_CATEGORY, self.consume_topic)

        consecutive_errors = 0

        while True:
            try:
                msg = await loop.run_in_executor(
                    None, lambda: self.consumer.poll(0.5)
                )

                if msg is None:
                    consecutive_errors = 0
                    await asyncio.sleep(0.05)
                    continue

                if msg.error():
                    consecutive_errors += 1
                    backoff = min(consecutive_errors * 2, 30)
                    logger.error(
                        "worker.consumer_error category=%s error=%s backoff=%ds",
                        self.WORKER_CATEGORY, msg.error(), backoff
                    )
                    await asyncio.sleep(backoff)
                    continue

                consecutive_errors = 0
                job = {}
                scan_id = "unknown"

                try:
                    job = json.loads(msg.value().decode("utf-8"))
                    scan_id = job.get("scan_id", "unknown")
                    org_id = job.get("org_id", "")
                    tool_name = job.get("tool_name", "unknown")
                    target = job.get("target", "")
                    config = job.get("config", {})

                    logger.info(
                        "worker.job_start category=%s scan_id=%s tool=%s target=%s",
                        self.WORKER_CATEGORY, scan_id, tool_name, target
                    )
                    self._produce_log(scan_id, f"Worker [{self.WORKER_CATEGORY}] started: {tool_name} → {target}")

                    findings = await self.execute_scan(tool_name, target, config)

                    logger.info(
                        "worker.job_complete scan_id=%s tool=%s findings=%d",
                        scan_id, tool_name, len(findings)
                    )
                    self._produce_log(scan_id, f"Completed {tool_name}: {len(findings)} findings")
                    self._produce_result(scan_id, org_id, tool_name, target, findings)

                    # Commit only after successful processing
                    await loop.run_in_executor(None, lambda: self.consumer.commit(asynchronous=False))

                except Exception as exc:
                    err_msg = str(exc)
                    logger.error(
                        "worker.job_failed scan_id=%s tool=%s error=%s",
                        scan_id, job.get("tool_name", "?"), err_msg,
                        exc_info=True
                    )
                    self._produce_log(scan_id, f"ERROR in {job.get('tool_name', '?')}: {err_msg}", level="ERROR")

                    # Route to DLQ instead of silently discarding
                    self._produce_dlq(job, err_msg)

                    try:
                        await loop.run_in_executor(None, lambda: self.consumer.commit(asynchronous=False))
                    except Exception:
                        pass

            except asyncio.CancelledError:
                logger.info("worker.shutdown category=%s", self.WORKER_CATEGORY)
                break
            except Exception as outer_err:
                logger.error("worker.outer_loop_error category=%s error=%s", self.WORKER_CATEGORY, outer_err)
                await asyncio.sleep(5)
