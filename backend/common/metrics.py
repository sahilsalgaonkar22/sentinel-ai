"""
SENTINEL AI — Custom Prometheus Metrics
Exposes scan-level observability counters and gauges beyond the default HTTP metrics.

Usage:
    from backend.common.metrics import (
        scans_total, findings_total, kafka_messages_total, active_scans
    )
    scans_total.labels(status="started").inc()
    findings_total.labels(severity="critical", tool_name="bandit").inc()
"""
try:
    from prometheus_client import Counter, Gauge, Histogram

    # ── Scan lifecycle counters ───────────────────────────────────────────────
    scans_total = Counter(
        "sentinel_scans_total",
        "Total number of scans triggered",
        ["status"],  # started | completed | failed
    )

    # ── Finding counters ──────────────────────────────────────────────────────
    findings_total = Counter(
        "sentinel_findings_total",
        "Total security findings discovered",
        ["severity", "tool_name"],  # critical/high/medium/low/info × tool
    )

    # ── Kafka producer metrics ────────────────────────────────────────────────
    kafka_messages_total = Counter(
        "sentinel_kafka_messages_total",
        "Total Kafka messages produced by the gateway",
        ["topic"],
    )

    # ── Active scan gauge ─────────────────────────────────────────────────────
    active_scans = Gauge(
        "sentinel_active_scans",
        "Number of scans currently in RUNNING state",
    )

    # ── Scan duration histogram ───────────────────────────────────────────────
    scan_duration_seconds = Histogram(
        "sentinel_scan_duration_seconds",
        "Time taken to complete a full scan pipeline",
        buckets=[30, 60, 120, 300, 600, 1800, 3600],
    )

    _metrics_enabled = True

except ImportError:
    # prometheus_client not installed — stub everything out so imports don't break
    class _Stub:
        def labels(self, **kwargs): return self
        def inc(self, amount=1): pass
        def dec(self, amount=1): pass
        def set(self, value): pass
        def observe(self, value): pass

    scans_total = _Stub()
    findings_total = _Stub()
    kafka_messages_total = _Stub()
    active_scans = _Stub()
    scan_duration_seconds = _Stub()
    _metrics_enabled = False
