"""
SENTINEL AI -- Finding Deduplication Engine
Uses content hashing + optional FAISS vector similarity.
Runs in the scan pipeline to eliminate duplicate findings before persistence.
"""
import hashlib
from typing import List, Dict, Tuple

try:
    import numpy as np
except ImportError:
    np = None

try:
    import faiss
except ImportError:
    faiss = None

SentenceTransformer = None
_embedder = None
try:
    from sentence_transformers import SentenceTransformer  # type: ignore
except Exception:  # noqa: BLE001 — catches NameError/AttributeError from PyTorch<2.4
    SentenceTransformer = None


def _finding_hash(finding: dict) -> str:
    """Generate a content hash for a finding based on key fields."""
    components = [
        finding.get("title", "").lower().strip(),
        finding.get("severity", "").lower(),
        finding.get("affected_component", "").lower().strip(),
        finding.get("tool_name", "").lower(),
        finding.get("cve_id", "").lower() if finding.get("cve_id") else "",
    ]
    content = "|".join(components)
    return hashlib.sha256(content.encode()).hexdigest()[:16]


def _finding_vector(finding: dict) -> list:
    """Generate a simple numeric feature vector for a finding (fallback)."""
    sev_map = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    sev_val = sev_map.get(finding.get("severity", "info"), 1)
    tool_map = {"bandit": 1, "semgrep": 2, "nmap": 3, "nikto": 4, "trivy": 5, "http_security": 6, "zap": 7, "masscan": 8, "pentagi": 9}
    tool_val = tool_map.get(finding.get("tool_name", ""), 0)
    title = finding.get("title", "").lower()
    title_words = title.split()
    word_hash = sum(hash(w) % 1000 for w in title_words) / max(len(title_words), 1)
    cvss = finding.get("cvss_score", 0.0) or 0.0
    comp = finding.get("affected_component", "")
    comp_val = hash(comp) % 1000 if comp else 0

    return [sev_val, tool_val, word_hash, cvss, comp_val, len(title), int(finding.get("exploit_available", False))]


def _get_embedding_text(finding: dict) -> str:
    """Construct a text representation for Semantic search/FAISS."""
    return f"{finding.get('title', '')}. Category: {finding.get('tool_name', '')}. Component: {finding.get('affected_component', '')}. Severity: {finding.get('severity', '')}"


def deduplicate_findings(findings: List[dict], threshold: float = 0.85) -> Tuple[List[dict], List[dict]]:
    """
    Remove duplicate/near-duplicate findings using strict hashes + FAISS vector similarity.
    """
    if not findings:
        return [], []

    seen_hashes = set()
    unique = []
    duplicates = []

    # Pass 1: Exact hash dedup
    for f in findings:
        h = _finding_hash(f)
        if h in seen_hashes:
            duplicates.append(f)
        else:
            seen_hashes.add(h)
            unique.append(f)

    # Pass 2: Semantic vector dedup (FAISS > Numpy > None)
    if len(unique) > 2:
        if faiss and SentenceTransformer and np:
            try:
                unique = _faiss_vector_dedup(unique, duplicates, threshold)
            except Exception as e:
                import logging
                logging.getLogger(__name__).warning("dedup.faiss_failed fallback=numpy error=%s", e)
                unique = _numpy_vector_dedup(unique, duplicates, threshold=0.95)
        elif np:
            unique = _numpy_vector_dedup(unique, duplicates, threshold=0.95)

    return unique, duplicates


def _faiss_vector_dedup(unique: List[dict], duplicates: List[dict], threshold: float) -> List[dict]:
    """Use FAISS index for high-performance semantic deduplication."""
    global _embedder
    if not _embedder:
        if SentenceTransformer is None:
            raise RuntimeError(
                "SentenceTransformer not available (PyTorch>=2.4 required). "
                "Falling back to numpy dedup."
            )
        try:
            _embedder = SentenceTransformer('all-MiniLM-L6-v2')
        except Exception as exc:
            raise RuntimeError(f"Could not load SentenceTransformer: {exc}") from exc
            
    texts = [_get_embedding_text(f) for f in unique]
    embeddings = _embedder.encode(texts, convert_to_numpy=True)
    
    # Normalize for cosine similarity (Inner Product)
    faiss.normalize_L2(embeddings)
    dim = embeddings.shape[1]
    
    index = faiss.IndexFlatIP(dim)
    index.add(embeddings)
    
    # Search top 5 neighbors
    D, I = index.search(embeddings, k=5)
    
    to_remove = set()
    for i in range(len(unique)):
        if i in to_remove:
            continue
        # I[i] contains neighbor indices, D[i] similarity scores
        for n_idx, dist in zip(I[i], D[i]):
            n_idx = int(n_idx)
            if n_idx <= i or n_idx in to_remove:
                continue
            if dist > threshold:
                sev_order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
                sev_i = sev_order.get(unique[i].get("severity"), 0)
                sev_j = sev_order.get(unique[n_idx].get("severity"), 0)
                
                # Keep higher severity
                if sev_j > sev_i:
                    to_remove.add(i)
                else:
                    to_remove.add(n_idx)
                    
                removed_item = unique[n_idx] if n_idx in to_remove else unique[i]
                duplicates.append(removed_item)

    return [f for idx, f in enumerate(unique) if idx not in to_remove]


def _numpy_vector_dedup(unique: List[dict], duplicates: List[dict], threshold: float) -> List[dict]:
    """Use simple numpy cosine similarity to find near-duplicates (Fallback)."""
    vectors = np.array([_finding_vector(f) for f in unique], dtype=np.float32)

    # Normalize
    norms = np.linalg.norm(vectors, axis=1, keepdims=True)
    norms[norms == 0] = 1
    normalized = vectors / norms
    similarity = normalized @ normalized.T

    to_remove = set()
    for i in range(len(unique)):
        if i in to_remove:
            continue
        for j in range(i + 1, len(unique)):
            if j in to_remove:
                continue
            if similarity[i, j] > threshold:
                sev_order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
                sev_i = sev_order.get(unique[i].get("severity"), 0)
                sev_j = sev_order.get(unique[j].get("severity"), 0)
                if sev_j > sev_i:
                    to_remove.add(i)
                else:
                    to_remove.add(j)
                duplicates.append(unique[j] if j in to_remove else unique[i])

    return [f for idx, f in enumerate(unique) if idx not in to_remove]


class Deduplicator:
    """Wrapper class providing the old API over the new deduplicate_findings function."""
    def __init__(self):
        self.findings = {}

    def add_finding(self, finding_id, finding_text):
        self.findings[finding_id] = finding_text

    def find_duplicates(self, finding_text, threshold=0.9):
        return []

    def deduplicate(self, findings_list):
        unique, dups = deduplicate_findings(findings_list)
        return unique

deduplicator = Deduplicator()
