"""
SENTINEL AI — Kafka → WebSocket Bridge (FIX-5: print → structured logging)

Consumes scan progress and completed events from Kafka and pushes them
to the relevant WebSocket clients in real-time.
"""
import asyncio
import json
import logging

from backend.services.kafka.manager import kafka_manager, TOPIC_SCAN_PROGRESS, TOPIC_SCAN_COMPLETED, TOPIC_FINDING_PROCESSED
from backend.gateway.routes.websocket_manager import manager

logger = logging.getLogger(__name__)


class RealtimeBridge:
    """SENTINEL AI — Kafka to WebSocket Bridge."""

    def __init__(self):
        self.group_id = "realtime-bridge"
        self.topics   = [TOPIC_SCAN_PROGRESS, TOPIC_SCAN_COMPLETED, TOPIC_FINDING_PROCESSED]

    async def run(self):
        """Consume Kafka events and push them to relevant WebSocket clients."""
        logger.info("realtime_bridge.started topics=%s", self.topics)
        consumer = kafka_manager.get_consumer(self.group_id, self.topics)

        try:
            loop = asyncio.get_running_loop()

            while True:
                # Run blocking poll in executor to avoid blocking event loop
                msg = await loop.run_in_executor(None, lambda: consumer.poll(1.0))
                if msg is None:
                    await asyncio.sleep(0.05)
                    continue

                if msg.error():
                    logger.error("realtime_bridge.kafka_error err=%s", msg.error())
                    await asyncio.sleep(1.0)
                    continue

                try:
                    event_data = json.loads(msg.value().decode("utf-8"))
                except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                    logger.warning("realtime_bridge.decode_error err=%s", exc)
                    continue

                topic = msg.topic()

                if topic == TOPIC_SCAN_PROGRESS:
                    scan_id = event_data.get("scan_id")
                    await manager.broadcast_scan_update(scan_id, event_data)

                elif topic == TOPIC_SCAN_COMPLETED:
                    scan_id = event_data.get("scan_id")
                    await manager.broadcast_scan_update(scan_id, {"status": "completed", "progress": 100})

                elif topic == TOPIC_FINDING_PROCESSED:
                    await manager.broadcast_finding(event_data)

                # Global broadcast for critical threat alerts
                if event_data.get("severity") == "critical":
                    await manager.broadcast_threat_alert(event_data)

        except asyncio.CancelledError:
            logger.info("realtime_bridge.cancelled")
        except Exception as exc:
            logger.critical("realtime_bridge.crashed err=%s", exc, exc_info=True)
            raise
        finally:
            consumer.close()
            logger.info("realtime_bridge.stopped")


if __name__ == "__main__":
    import logging as _logging
    _logging.basicConfig(level=_logging.INFO)
    bridge = RealtimeBridge()
    asyncio.run(bridge.run())
