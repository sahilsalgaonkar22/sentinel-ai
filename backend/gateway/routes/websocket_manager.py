"""
SENTINEL AI — WebSocket Connection Manager (Redis Pub/Sub — Multi-Worker Safe)

FIX-3 (CRITICAL): Replaced in-memory ConnectionManager with Redis pub/sub.
- In-memory state only works with 1 worker. All production deployments run ≥ 2.
- Now: scan updates are published to Redis channel `scan_updates:{scan_id}`.
  Every worker subscribes and fans out to its local WebSocket connections.
- Each gateway instance maintains its OWN active_connections map (per-process).
  The inter-process broadcast happens entirely via Redis, not shared memory.

IDOR FIX: subscribe_to_scan() validates org ownership via DB before granting access.
"""
import asyncio
import json
import logging
from fastapi import WebSocket
from typing import Dict, Set, Optional

logger = logging.getLogger(__name__)


class RedisConnectionManager:
    """
    Multi-worker-safe WebSocket connection manager backed by Redis pub/sub.

    Architecture:
      - Each gateway worker tracks its own connections in `active_connections`.
      - Messages are published to Redis channels; all workers consume and deliver.
      - No shared in-process state across replicas.

    Redis Channel Schema:
      scan_updates:{scan_id}    → per-scan progress updates
      finding_stream            → all processed findings (broadcast)
      threat_alerts             → critical severity alerts (broadcast)
    """

    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.scan_subscriptions: Dict[str, Set[str]] = {}   # scan_id → {client_id}
        self._client_org: Dict[str, str] = {}
        self._redis = None
        self._pubsub = None
        self._listener_task: Optional[asyncio.Task] = None

    async def initialize(self, redis_client) -> None:
        """
        Bind this manager to the application-level Redis client.
        Call once during FastAPI lifespan startup, after Redis is connected.
        Starts the background pub/sub listener.
        """
        self._redis = redis_client
        self._pubsub = redis_client.pubsub()
        # Subscribe to patterns for all scan channels + global feeds
        await self._pubsub.psubscribe(
            "scan_updates:*",
            "finding_stream",
            "threat_alerts",
        )
        self._listener_task = asyncio.create_task(
            self._pubsub_listener(), name="ws_pubsub_listener"
        )
        logger.info("ws_manager.redis_pubsub_initialized")

    async def shutdown(self) -> None:
        """Cancel background listener and clean up pub/sub subscription."""
        if self._listener_task:
            self._listener_task.cancel()
            try:
                await self._listener_task
            except asyncio.CancelledError:
                pass
        if self._pubsub:
            await self._pubsub.punsubscribe()
            await self._pubsub.aclose()
        logger.info("ws_manager.shutdown")

    # ── Redis Pub/Sub Listener ────────────────────────────────────────────────

    async def _pubsub_listener(self) -> None:
        """
        Background task: consume Redis pub/sub messages and deliver
        to local WebSocket connections. Runs indefinitely.
        """
        logger.info("ws_manager.pubsub_listener.started")
        try:
            async for message in self._pubsub.listen():
                if message["type"] not in ("pmessage", "message"):
                    continue
                try:
                    channel = message.get("channel", "")
                    if isinstance(channel, bytes):
                        channel = channel.decode("utf-8")
                    data_raw = message.get("data", "")
                    if isinstance(data_raw, bytes):
                        data_raw = data_raw.decode("utf-8")
                    if not data_raw or data_raw == "1":
                        continue

                    payload = json.loads(data_raw)

                    if channel.startswith("scan_updates:"):
                        scan_id = channel.split(":", 1)[1]
                        await self._local_broadcast_scan(scan_id, payload)

                    elif channel == "finding_stream":
                        await self._local_broadcast_all(payload)

                    elif channel == "threat_alerts":
                        await self._local_broadcast_all(payload)

                except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                    logger.warning("ws_manager.pubsub_decode_error err=%s", exc)
                except Exception as exc:
                    logger.error("ws_manager.pubsub_error err=%s", exc, exc_info=True)

        except asyncio.CancelledError:
            logger.info("ws_manager.pubsub_listener.cancelled")
        except Exception as exc:
            logger.critical("ws_manager.pubsub_listener.crashed err=%s", exc, exc_info=True)

    # ── Connection Lifecycle ──────────────────────────────────────────────────

    async def connect(self, websocket: WebSocket, client_id: str, org_id: str = "") -> None:
        await websocket.accept()
        self.active_connections[client_id] = websocket
        if org_id:
            self._client_org[client_id] = org_id
        await self._send_local(client_id, {
            "type": "connected",
            "message": "SENTINEL AI — Neural stream synced",
            "client_id": client_id,
        })
        logger.info("ws.connected client_id=%s org_id=%s", client_id, org_id)

    def disconnect(self, client_id: str) -> None:
        self.active_connections.pop(client_id, None)
        self._client_org.pop(client_id, None)
        for scan_id in list(self.scan_subscriptions.keys()):
            self.scan_subscriptions[scan_id].discard(client_id)
        logger.info("ws.disconnected client_id=%s", client_id)

    async def subscribe_to_scan(
        self,
        client_id: str,
        scan_id: str,
        org_id: str,
        db,                # AsyncSession — caller provides
    ) -> bool:
        """
        IDOR FIX: Validate that scan_id belongs to org_id before subscribing.
        Returns True on success, False on unauthorized.
        """
        from backend.services.scan_control.models import Scan   # lazy import

        scan = await db.get(Scan, scan_id)
        if not scan or scan.org_id != org_id:
            logger.warning(
                "ws.subscription_denied client_id=%s scan_id=%s org_id=%s",
                client_id, scan_id, org_id
            )
            return False

        self.scan_subscriptions.setdefault(scan_id, set()).add(client_id)
        logger.info("ws.subscribed client_id=%s scan_id=%s org_id=%s", client_id, scan_id, org_id)
        return True

    # ── Publish via Redis (multi-worker broadcast) ────────────────────────────

    async def broadcast_scan_update(self, scan_id: str, data: dict) -> None:
        """Publish scan update to Redis — all workers fan out to their local clients."""
        if not self._redis:
            logger.error("ws_manager.redis_not_initialized cannot publish scan_update")
            return
        message = {"type": "scan_update", "scan_id": scan_id, **data}
        try:
            await self._redis.publish(f"scan_updates:{scan_id}", json.dumps(message))
        except Exception as exc:
            logger.error("ws_manager.publish_error channel=scan_updates:%s err=%s", scan_id, exc)

    async def broadcast_finding(self, finding: dict) -> None:
        """Publish a processed finding to all subscribers."""
        if not self._redis:
            return
        message = {"type": "finding", **finding}
        try:
            await self._redis.publish("finding_stream", json.dumps(message))
        except Exception as exc:
            logger.error("ws_manager.publish_error channel=finding_stream err=%s", exc)

    async def broadcast_threat_alert(self, alert: dict) -> None:
        """Publish a critical threat alert to all connected clients."""
        if not self._redis:
            return
        message = {"type": "threat_alert", **alert}
        try:
            await self._redis.publish("threat_alerts", json.dumps(message))
        except Exception as exc:
            logger.error("ws_manager.publish_error channel=threat_alerts err=%s", exc)

    # ── Local Delivery (this worker's clients only) ───────────────────────────

    async def _local_broadcast_scan(self, scan_id: str, message: dict) -> None:
        """Fan out a scan message to local connections subscribed to this scan."""
        for client_id in list(self.scan_subscriptions.get(scan_id, set())):
            await self._send_local(client_id, message)

    async def _local_broadcast_all(self, message: dict) -> None:
        """Fan out a message to ALL local connections."""
        disconnected = []
        for client_id, ws in list(self.active_connections.items()):
            try:
                await ws.send_text(json.dumps(message))
            except Exception:
                disconnected.append(client_id)
        for cid in disconnected:
            self.disconnect(cid)

    async def _send_local(self, client_id: str, message: dict) -> None:
        ws = self.active_connections.get(client_id)
        if ws:
            try:
                await ws.send_text(json.dumps(message))
            except Exception as exc:
                logger.warning("ws.send_error client_id=%s err=%s", client_id, exc)
                self.disconnect(client_id)

    async def send_personal(self, client_id: str, message: dict) -> None:
        """Send directly to a single client (used for heartbeat, errors)."""
        await self._send_local(client_id, message)

    async def push_log_line(self, scan_id: str, tool: str, log_line: str, level: str = "INFO") -> None:
        """Push a single log line to scan subscribers via Redis."""
        await self.broadcast_scan_update(scan_id, {
            "type": "scan_log",
            "scan_id": scan_id,
            "tool": tool,
            "level": level,
            "message": log_line,
        })

    def get_active_connection_count(self) -> int:
        return len(self.active_connections)


# Singleton — initialized at startup via manager.initialize(redis_client)
manager = RedisConnectionManager()
