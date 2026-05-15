"""
SENTINEL AI — Elasticsearch Client
Indexes findings and scan logs for full-text search.
Gracefully degrades to no-op when ELASTICSEARCH_URL is not set.
"""
from __future__ import annotations
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

try:
    from elasticsearch import AsyncElasticsearch
    _ES_AVAILABLE = True
except ImportError:
    AsyncElasticsearch = None  # type: ignore
    _ES_AVAILABLE = False


# ── Index names ──────────────────────────────────────────────────────────────
INDEX_FINDINGS = "sentinel-findings"
INDEX_SCANS    = "sentinel-scans"
INDEX_LOGS     = "sentinel-logs"

# ── Index mappings ───────────────────────────────────────────────────────────
_FINDING_MAPPING = {
    "mappings": {
        "properties": {
            "id":                  {"type": "keyword"},
            "scan_id":             {"type": "keyword"},
            "org_id":              {"type": "keyword"},
            "title":               {"type": "text", "analyzer": "standard"},
            "description":         {"type": "text", "analyzer": "standard"},
            "severity":            {"type": "keyword"},
            "cvss_score":          {"type": "float"},
            "cve_id":              {"type": "keyword"},
            "cwe_id":              {"type": "keyword"},
            "tool_name":           {"type": "keyword"},
            "affected_component":  {"type": "text"},
            "remediation":         {"type": "text"},
            "exploit_available":   {"type": "boolean"},
            "is_false_positive":   {"type": "boolean"},
            "ai_risk_score":       {"type": "float"},
            "indexed_at":          {"type": "date"},
        }
    }
}

_SCAN_MAPPING = {
    "mappings": {
        "properties": {
            "id":             {"type": "keyword"},
            "org_id":         {"type": "keyword"},
            "name":           {"type": "text"},
            "target":         {"type": "keyword"},
            "scan_type":      {"type": "keyword"},
            "status":         {"type": "keyword"},
            "security_score": {"type": "float"},
            "risk_grade":     {"type": "keyword"},
            "started_at":     {"type": "date"},
            "completed_at":   {"type": "date"},
        }
    }
}


class ElasticsearchClient:
    """
    Async Elasticsearch client for Sentinel AI.

    REAL path:  ELASTICSEARCH_URL set + elasticsearch-py installed → real indexing
    FALLBACK:   ES not configured → all operations are no-ops (never raises)
    """

    def __init__(self):
        self.client: Optional[AsyncElasticsearch] = None
        self.enabled = False

    async def connect(self, url: str) -> None:
        """Initialize connection and ensure indices exist."""
        if not url:
            logger.warning("[ES] ELASTICSEARCH_URL not set. Search indexing disabled.")
            return
        if not _ES_AVAILABLE:
            logger.warning(
                "[ES] elasticsearch package not installed. "
                "Run: pip install elasticsearch"
            )
            return
        try:
            self.client = AsyncElasticsearch(url, request_timeout=10)
            # Ping to verify connection
            await self.client.ping()
            self.enabled = True
            logger.info("[ES] Connected to Elasticsearch at %s", url)
            await self._ensure_indices()
        except Exception as exc:
            logger.error("[ES] Failed to connect: %s. Indexing disabled.", exc)
            self.client = None

    async def _ensure_indices(self) -> None:
        """Create indices with mappings if they don't exist."""
        if not self.client:
            return
        for index, mapping in [
            (INDEX_FINDINGS, _FINDING_MAPPING),
            (INDEX_SCANS,    _SCAN_MAPPING),
        ]:
            try:
                exists = await self.client.indices.exists(index=index)
                if not exists:
                    await self.client.indices.create(index=index, body=mapping)
                    logger.info("[ES] Created index: %s", index)
            except Exception as exc:
                logger.warning("[ES] Could not create index %s: %s", index, exc)

    # ── Public indexing API ──────────────────────────────────────────────────

    async def index_finding(self, finding: Dict[str, Any]) -> None:
        """Index a single finding. No-op if ES is disabled."""
        if not self.enabled or not self.client:
            return
        try:
            from datetime import datetime, timezone
            doc = {**finding, "indexed_at": datetime.now(timezone.utc).isoformat()}
            await self.client.index(
                index=INDEX_FINDINGS,
                id=finding.get("id"),
                document=doc,
            )
        except Exception as exc:
            logger.warning("[ES] index_finding failed: %s", exc)

    async def index_findings_bulk(self, findings: List[Dict[str, Any]]) -> None:
        """Bulk index findings. No-op if ES is disabled."""
        if not self.enabled or not self.client or not findings:
            return
        try:
            from elasticsearch.helpers import async_bulk
            from datetime import datetime, timezone
            now = datetime.now(timezone.utc).isoformat()

            actions = [
                {
                    "_index": INDEX_FINDINGS,
                    "_id": f.get("id"),
                    "_source": {**f, "indexed_at": now},
                }
                for f in findings
            ]
            success, errors = await async_bulk(self.client, actions, raise_on_error=False)
            if errors:
                logger.warning("[ES] Bulk index had %d errors", len(errors))
            else:
                logger.info("[ES] Bulk indexed %d findings", success)
        except Exception as exc:
            logger.warning("[ES] index_findings_bulk failed: %s", exc)

    async def index_scan(self, scan: Dict[str, Any]) -> None:
        """Index a scan record. No-op if ES is disabled."""
        if not self.enabled or not self.client:
            return
        try:
            await self.client.index(
                index=INDEX_SCANS,
                id=scan.get("id"),
                document=scan,
            )
        except Exception as exc:
            logger.warning("[ES] index_scan failed: %s", exc)

    async def search_findings(
        self,
        query: str,
        org_id: str,
        severity: Optional[str] = None,
        page: int = 1,
        per_page: int = 20,
    ) -> Dict[str, Any]:
        """
        Full-text search over findings for a specific org.
        Returns PostgreSQL-compatible empty result if ES is disabled.
        """
        if not self.enabled or not self.client:
            return {"total": 0, "items": [], "source": "elasticsearch_disabled"}

        must_clauses: List[Dict] = [
            {"term": {"org_id": org_id}},
            {
                "multi_match": {
                    "query": query,
                    "fields": ["title^3", "description^2", "cve_id^3", "affected_component", "remediation"],
                    "type": "best_fields",
                    "fuzziness": "AUTO",
                }
            }
        ]
        if severity:
            must_clauses.append({"term": {"severity": severity.lower()}})

        try:
            resp = await self.client.search(
                index=INDEX_FINDINGS,
                body={
                    "query": {"bool": {"must": must_clauses}},
                    "from": (page - 1) * per_page,
                    "size": per_page,
                    "sort": [{"cvss_score": {"order": "desc"}}, "_score"],
                },
            )
            hits = resp["hits"]
            return {
                "total": hits["total"]["value"],
                "items": [h["_source"] for h in hits["hits"]],
                "source": "elasticsearch",
            }
        except Exception as exc:
            logger.warning("[ES] search_findings failed: %s", exc)
            return {"total": 0, "items": [], "source": "elasticsearch_error"}

    async def delete_finding(self, finding_id: str) -> None:
        """Remove a finding from the index."""
        if not self.enabled or not self.client:
            return
        try:
            await self.client.delete(index=INDEX_FINDINGS, id=finding_id, ignore=[404])
        except Exception as exc:
            logger.warning("[ES] delete_finding failed: %s", exc)

    async def close(self) -> None:
        """Cleanly close the ES connection on shutdown."""
        if self.client:
            try:
                await self.client.close()
            except Exception:
                pass


# Singleton
es_client = ElasticsearchClient()
