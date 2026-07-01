"""
In-process query engine for the 3 ChromaDB databases.

Replaces the old subprocess-based approach with direct ChromaDB clients.
All queries run in parallel via asyncio + ThreadPoolExecutor.
Results are cached per target-spec hash to avoid redundant work across
loop-controller retries.

Databases:
  1. malware_techniques  — evasion/injection/persistence technique corpus
  2. poc_exploits        — CVE PoC exploit code (full source available)
  3. cti_intel           — CTI intelligence from hermes/qwen research

Query plan:
  Instead of one generic query string for all DBs, we build purpose-specific
  queries from the target spec:
    - malware:  per-EDR evasion queries + OS-specific technique queries
    - poc:      OS version queries + CVE-targeted lookups + exploit-type queries
    - cti:      threat landscape queries + CVE cross-reference
"""

import asyncio
import hashlib
import logging
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Dict, Any, Set

from .db_models import MalwareTechnique, PoC, CTIFinding, QueryResult

logger = logging.getLogger(__name__)

_CVE_PAT = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)

# DB paths
_MALWARE_CORPUS = Path("/home/kei/llm_vault/malware_corpus")
_MALWARE_CHROMA = str(_MALWARE_CORPUS / "data" / "chroma")
_POC_CHROMA = str(_MALWARE_CORPUS / "data" / "poc_chroma")
_CTI_CHROMA = str(Path("/home/kei/llm_vault/hermes_qwen_cti") / "data" / "chroma")

_MALWARE_COLLECTION = "malware_techniques"
_POC_COLLECTION = "poc_exploits"
_CTI_COLLECTION = "cti_intel"


# ---------------------------------------------------------------------------
# Query plan — computed once from target spec, drives all DB queries
# ---------------------------------------------------------------------------

@dataclass
class QueryPlan:
    """All query terms needed for a generation run, computed upfront."""
    malware_queries: List[Dict[str, Any]] = field(default_factory=list)
    poc_queries: List[Dict[str, Any]] = field(default_factory=list)
    cti_queries: List[Dict[str, Any]] = field(default_factory=list)
    poc_cve_lookups: List[str] = field(default_factory=list)
    cache_key: str = ""

    @staticmethod
    def from_target_spec(spec: Any) -> "QueryPlan":
        plan = QueryPlan()
        os_platform = spec.os_platform.value if hasattr(spec.os_platform, "value") else str(spec.os_platform)
        os_version = spec.os_version
        edrs = spec.edrs or []
        patch_level = spec.patch_level or ""
        malware_type = getattr(spec, "malware_type", "exe")

        # -- malware corpus queries: EDR-specific + OS + malware-type -----------
        for edr in edrs:
            if not edr:
                continue
            plan.malware_queries.append({
                "text": f"{edr} evasion bypass",
                "where": {"edr_tags": {"$eq": edr}},
                "n": 8,
                "tag": f"edr:{edr}",
            })
        plan.malware_queries.append({
            "text": f"{os_platform} {os_version} evasion techniques",
            "where": {"target_os": {"$eq": os_platform}} if os_platform in ("windows", "linux") else None,
            "n": 10,
            "tag": "os_general",
        })
        if malware_type and malware_type not in ("exe",):
            plan.malware_queries.append({
                "text": f"{malware_type} {os_platform} techniques",
                "where": None,
                "n": 6,
                "tag": f"type:{malware_type}",
            })
        for category in ("evasion", "persistence", "injection"):
            plan.malware_queries.append({
                "text": f"{os_platform} {category}",
                "where": {"category": {"$eq": category}},
                "n": 5,
                "tag": f"cat:{category}",
            })
            plan.malware_queries.append({
                "text": f"{os_platform} {category} technique implementation",
                "where": None,
                "n": 5,
                "tag": f"cat_open:{category}",
            })

        # -- Malware-type-specific queries (decompiled real malware) ----
        _TYPE_QUERIES = {
            "ransomware": [
                "file encryption CryptEncrypt AES ransomware",
                "file enumeration FindFirstFile directory traversal encrypt",
                "ransom note payment bitcoin wallet address",
                "registry persistence Run key startup ransomware",
                "shadow copy deletion vssadmin wmic",
                "process killing taskkill anti-recovery",
            ],
            "backdoor": [
                "reverse shell C2 command control backdoor",
                "keylogger keyboard hook credential capture",
                "process injection CreateRemoteThread hollowing",
            ],
            "stealer": [
                "browser credential theft Chrome Firefox password",
                "LSASS memory dump credential harvesting",
                "clipboard monitor cryptocurrency wallet",
            ],
        }
        for term in _TYPE_QUERIES.get(malware_type, []):
            plan.malware_queries.append({
                "text": term,
                "where": {"target_os": {"$eq": os_platform}} if os_platform in ("windows", "linux") else None,
                "n": 5,
                "tag": f"type_specific:{malware_type}",
            })

        # -- Decompiled malware structural references ----
        plan.malware_queries.append({
            "text": f"{malware_type} {os_platform} architecture implementation structure",
            "where": {"source": {"$eq": "decompiled"}},
            "n": 8,
            "tag": "decompiled_ref",
        })

        # -- PoC queries: OS-version targeted + exploit-type + CVE lookups ------
        poc_terms = _build_poc_terms(os_platform, os_version)
        for term in poc_terms:
            plan.poc_queries.append({
                "text": term,
                "where": None,
                "n": 8,
                "tag": f"poc:{term}",
            })
        for etype in ("privilege escalation", "local privilege escalation", "RCE"):
            plan.poc_queries.append({
                "text": f"{os_platform} {etype}",
                "where": None,
                "n": 5,
                "tag": f"poc_type:{etype}",
            })
        if patch_level:
            plan.poc_queries.append({
                "text": f"{os_platform} {os_version} {patch_level}",
                "where": None,
                "n": 5,
                "tag": f"poc_patch:{patch_level}",
            })

        # -- CTI queries: threat landscape + OS-specific -----------------------
        plan.cti_queries.append({
            "text": f"{os_platform} {os_version} vulnerability exploitation",
            "n": 8,
            "tag": "cti_os",
        })
        plan.cti_queries.append({
            "text": f"privilege escalation {os_platform}",
            "n": 5,
            "tag": "cti_privesc",
        })
        if edrs:
            edr_str = " ".join(e for e in edrs if e)
            if edr_str:
                plan.cti_queries.append({
                    "text": f"{edr_str} evasion bypass detection",
                    "n": 5,
                    "tag": "cti_edr",
                })
        plan.cti_queries.append({
            "text": f"recent exploit {os_platform} 2024 2025",
            "n": 5,
            "tag": "cti_recent",
        })

        # -- cache key ----------------------------------------------------------
        key_parts = [
            os_platform, os_version, patch_level, malware_type,
            ",".join(sorted(edrs)),
        ]
        plan.cache_key = hashlib.sha256("|".join(key_parts).encode()).hexdigest()[:16]

        return plan


def _build_poc_terms(os_platform: str, os_version: str) -> List[str]:
    terms = set()
    os_ver_lower = os_version.lower()

    if "ubuntu" in os_ver_lower or "debian" in os_ver_lower:
        terms.add("linux")
        terms.add("linux privilege escalation")
        parts = os_ver_lower.split("-")
        if len(parts) > 1:
            ver = parts[1]
            terms.add(f"ubuntu {ver}")
    elif "windows" in os_ver_lower:
        terms.add("windows")
        terms.add("windows privilege escalation")
        if "11" in os_ver_lower:
            terms.update(["windows 11", "windows 11 exploit", "windows 2024"])
        elif "10" in os_ver_lower:
            terms.update(["windows 10", "windows 10 exploit"])

    terms.add(f"{os_platform} exploit")
    return list(terms)


# ---------------------------------------------------------------------------
# ChromaDB connection pool — lazy singleton per DB
# ---------------------------------------------------------------------------

class _ChromaPool:
    """Thread-safe ChromaDB connection pool.

    ChromaDB PersistentClient is NOT thread-safe, so we use threading.local
    to give each executor thread its own client + collection instances.
    The embedding function is shared (stateless, thread-safe).
    """

    def __init__(self):
        import threading
        self._local = threading.local()
        self._ef = None
        self._ef_lock = threading.Lock()

    def _get_ef(self):
        if self._ef is None:
            with self._ef_lock:
                if self._ef is None:
                    from chromadb.utils.embedding_functions import DefaultEmbeddingFunction
                    self._ef = DefaultEmbeddingFunction()
        return self._ef

    def _get_or_create(self, attr: str, chroma_path: str, collection_name: str):
        local = self._local
        col = getattr(local, attr, None)
        if col is not None:
            return col
        if not Path(chroma_path).is_dir():
            raise FileNotFoundError(
                f"ChromaDB directory not found: {chroma_path} — "
                f"ensure the database has been built before running the pipeline"
            )
        import chromadb
        client = chromadb.PersistentClient(path=chroma_path)
        col = client.get_or_create_collection(
            name=collection_name,
            embedding_function=self._get_ef(),
            metadata={"hnsw:space": "cosine"},
        )
        setattr(local, attr, col)
        logger.info("ChromaDB %s: %d docs (thread %s)",
                     collection_name, col.count(),
                     __import__("threading").current_thread().name)
        return col

    def malware(self):
        return self._get_or_create("_malware_col", _MALWARE_CHROMA, _MALWARE_COLLECTION)

    def poc(self):
        return self._get_or_create("_poc_col", _POC_CHROMA, _POC_COLLECTION)

    def cti(self):
        return self._get_or_create("_cti_col", _CTI_CHROMA, _CTI_COLLECTION)


_pool = _ChromaPool()


# ---------------------------------------------------------------------------
# Raw query functions (sync — run inside executor)
# ---------------------------------------------------------------------------

def _query_malware_semantic(query_text: str, n: int, where: Optional[dict]) -> list:
    col = _pool.malware()
    total = col.count()
    if total == 0:
        return []
    kwargs = dict(
        query_texts=[query_text],
        n_results=min(n, total),
        include=["documents", "metadatas", "distances"],
    )
    if where:
        try:
            kwargs["where"] = where
            return col.query(**kwargs)
        except Exception:
            del kwargs["where"]
    return col.query(**kwargs)


def _query_poc_semantic(query_text: str, n: int, where: Optional[dict]) -> list:
    col = _pool.poc()
    total = col.count()
    if total == 0:
        return []
    fetch = min(max(n * 4, 20), total)
    kwargs = dict(
        query_texts=[query_text],
        n_results=fetch,
        include=["documents", "metadatas", "distances"],
    )
    if where:
        try:
            kwargs["where"] = where
            return col.query(**kwargs)
        except Exception:
            del kwargs["where"]
    return col.query(**kwargs)


def _query_poc_by_cve(cve_id: str, n: int = 10) -> list:
    """Exact CVE metadata lookup — bypasses vector search."""
    col = _pool.poc()
    if col.count() == 0:
        return []
    normalised = cve_id.strip().upper()
    result = col.get(
        where={"cve": {"$eq": normalised}},
        include=["documents", "metadatas"],
    )
    items = list(zip(
        result.get("ids", []),
        result.get("documents", []),
        result.get("metadatas", []),
    ))
    items.sort(key=lambda x: int(x[2].get("stars", 0) or 0), reverse=True)
    return items[:n]


def _query_cti_semantic(query_text: str, n: int, threshold: float = 0.6) -> list:
    col = _pool.cti()
    total = col.count()
    if total == 0:
        return []
    fetch = min(max(n * 4, 20), total)
    results = col.query(
        query_texts=[query_text],
        n_results=fetch,
        include=["documents", "metadatas", "distances"],
    )
    filtered = []
    keyword = query_text.lower()
    for doc, meta, dist in zip(
        results["documents"][0],
        results["metadatas"][0],
        results["distances"][0],
    ):
        effective_dist = dist
        if keyword in doc.lower():
            effective_dist = min(dist, 0.50)
        if effective_dist <= threshold:
            filtered.append((doc, meta, effective_dist))
    filtered.sort(key=lambda x: x[2])
    return filtered[:n]


def _load_poc_fullfile(filepath: str) -> str:
    """Read full PoC source from disk for exploit integration."""
    if not filepath:
        return ""
    resolved = (_MALWARE_CORPUS / filepath).resolve()
    try:
        resolved.relative_to(_MALWARE_CORPUS)
    except ValueError:
        return ""
    if not resolved.exists():
        return ""
    sig = resolved.read_bytes()[:4]
    if sig[:2] == b"MZ" or sig[:4] == b"\x7fELF":
        return ""
    try:
        return resolved.read_text(errors="replace")
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Result parsing helpers
# ---------------------------------------------------------------------------

def _parse_malware_results(raw: dict) -> List[MalwareTechnique]:
    if not raw or not raw.get("ids"):
        return []
    ids = raw["ids"][0]
    docs = raw["documents"][0]
    metas = raw["metadatas"][0]
    dists = raw["distances"][0]
    techniques = []
    for doc_id, doc, meta, dist in zip(ids, docs, metas, dists):
        sim = 1 - dist
        lines = doc.splitlines()
        header_lines, code_lines, in_header = [], [], True
        for line in lines:
            if in_header and line.startswith(("Description:", "Category:", "Target OS:",
                                              "Language:", "EDR/AV relevance:",
                                              "Techniques:", "File:")):
                header_lines.append(line)
            else:
                in_header = False
                code_lines.append(line)
        techniques.append(MalwareTechnique(
            id=doc_id,
            name=meta.get("filename", ""),
            description="\n".join(header_lines),
            category=meta.get("category", ""),
            os_type=meta.get("target_os", ""),
            edr_detection=meta.get("edr_tags", ""),
            detection_rating=round(1 - sim, 2),
            similarity=round(sim, 4),
            source_code="\n".join(code_lines).strip(),
            filepath=meta.get("filepath", ""),
            references=[meta.get("repo", "")],
        ))
    return techniques


def _extract_code_from_doc(doc: str) -> str:
    """Extract source code from a PoC document, skipping the metadata header."""
    lines = doc.splitlines()
    code_lines = []
    in_header = True
    for line in lines:
        if in_header and line.startswith((
            "CVE:", "Repository:", "File:", "Language:",
            "Stars:", "Description:", "Forks:",
        )):
            continue
        in_header = False
        code_lines.append(line)
    code = "\n".join(code_lines).strip()
    return code


def _parse_poc_from_doc(doc_id: str, doc: str, meta: dict, dist: float = 0.0) -> PoC:
    """Parse a single PoC from its ChromaDB document + metadata."""
    filepath = meta.get("filepath", "")
    file_type = meta.get("file_type", "")
    cve_str = meta.get("cve", "")
    year_match = re.search(r"CVE-(\d{4})", cve_str)

    # Extract source code: from document text for code files, from disk as fallback
    full_source = ""
    if file_type == "code":
        full_source = _extract_code_from_doc(doc)
    if not full_source and filepath and filepath != "README":
        full_source = _load_poc_fullfile(filepath)

    return PoC(
        id=doc_id,
        cve=cve_str,
        title=meta.get("repo_name", ""),
        description=doc[:500],
        exploit_type=meta.get("language", ""),
        target_os="",
        severity="medium",
        source=meta.get("repo_url", ""),
        code=doc[:500],
        full_source=full_source if full_source else None,
        filepath=filepath,
        language=meta.get("language", ""),
        stars=int(meta.get("stars", 0) or 0),
        forks=int(meta.get("forks", 0) or 0),
        cve_year=int(year_match.group(1)) if year_match else None,
        references=[filepath] if filepath else [],
    )


def _parse_poc_semantic(raw: dict) -> List[PoC]:
    if not raw or not raw.get("ids"):
        return []
    ids = raw["ids"][0]
    docs = raw["documents"][0]
    metas = raw["metadatas"][0]
    dists = raw["distances"][0]
    return [
        _parse_poc_from_doc(doc_id, doc, meta, dist)
        for doc_id, doc, meta, dist in zip(ids, docs, metas, dists)
    ]


def _parse_poc_cve_lookup(items: list) -> List[PoC]:
    return [
        _parse_poc_from_doc(row[0], row[1], row[2])
        for row in items
    ]


def _parse_cti_results(items: list) -> List[CTIFinding]:
    findings = []
    for doc, meta, dist in items:
        cve = meta.get("cve", "")
        poc_urls_str = meta.get("poc_urls", "")
        poc_urls = [u.strip() for u in poc_urls_str.split("|") if u.strip()] if poc_urls_str else []
        findings.append(CTIFinding(
            id=meta.get("_id", "") or meta.get("uuid", ""),
            title="",
            description=doc[:800],
            severity=meta.get("severity", "medium"),
            similarity=round(1 - dist, 4),
            threat_actor="",
            related_cves=[cve] if cve else [],
            references=[meta.get("url", "")] if meta.get("url") else [],
            poc_urls=poc_urls,
            date=meta.get("date", "")[:10],
        ))
    return findings


# ---------------------------------------------------------------------------
# Main engine — public API
# ---------------------------------------------------------------------------

class DBQueryEngine:
    """In-process query engine with parallel execution and result caching."""

    def __init__(
        self,
        malware_corpus_path: str = str(_MALWARE_CORPUS),
        cti_db_path: str = str(Path("/home/kei/llm_vault/hermes_qwen_cti")),
        max_workers: int = 6,
    ):
        self._executor = ThreadPoolExecutor(max_workers=max_workers)
        self._cache: Dict[str, QueryResult] = {}
        self._disk_cache_dir = Path(__file__).parent / ".cache" / "db_queries"
        self._disk_cache_dir.mkdir(parents=True, exist_ok=True)

    # -- cache management ---------------------------------------------------

    def clear_cache(self):
        self._cache.clear()

    # -- unified async entry point ------------------------------------------

    async def query_unified(self, target_spec: Any) -> QueryResult:
        """Execute the full query plan for a target spec.

        Builds purpose-specific queries, runs them all in parallel,
        deduplicates, and returns a single QueryResult.
        Cached by target spec hash — free on retry loops.
        """
        plan = QueryPlan.from_target_spec(target_spec)

        if plan.cache_key in self._cache:
            logger.info("DB query cache HIT (%s)", plan.cache_key)
            return self._cache[plan.cache_key]

        disk_path = self._disk_cache_dir / f"{plan.cache_key}.json"
        if disk_path.exists():
            try:
                import json as _json
                from dataclasses import fields as _fields
                raw = _json.loads(disk_path.read_text())
                result = QueryResult(
                    malware_techniques=[MalwareTechnique(**t) for t in raw.get("malware_techniques", [])],
                    poc_results=[PoC(**p) for p in raw.get("poc_results", [])],
                    cti_findings=[CTIFinding(**c) for c in raw.get("cti_findings", [])],
                    cve_pocs=[PoC(**p) for p in raw.get("cve_pocs", [])],
                )
                self._cache[plan.cache_key] = result
                logger.info("DB query DISK cache HIT (%s): %d techniques, %d pocs",
                            plan.cache_key, len(result.malware_techniques), len(result.poc_results))
                return result
            except Exception as exc:
                logger.warning("Disk cache load failed (%s): %s", plan.cache_key, exc)
                disk_path.unlink(missing_ok=True)

        logger.info("DB query plan: %d malware, %d poc, %d cti queries, %d CVE lookups",
                     len(plan.malware_queries), len(plan.poc_queries),
                     len(plan.cti_queries), len(plan.poc_cve_lookups))

        # Pre-warm ChromaDB connections on the main thread so the embedding
        # function and tenant are initialized before parallel dispatch.
        _pool.malware()
        _pool.poc()
        _pool.cti()

        loop = asyncio.get_event_loop()

        # Fire all queries in parallel
        malware_futures = [
            loop.run_in_executor(
                self._executor,
                _query_malware_semantic, q["text"], q["n"], q.get("where"),
            )
            for q in plan.malware_queries
        ]
        poc_futures = [
            loop.run_in_executor(
                self._executor,
                _query_poc_semantic, q["text"], q["n"], q.get("where"),
            )
            for q in plan.poc_queries
        ]
        cti_futures = [
            loop.run_in_executor(
                self._executor,
                _query_cti_semantic, q["text"], q["n"], 0.6,
            )
            for q in plan.cti_queries
        ]
        cve_futures = [
            loop.run_in_executor(
                self._executor,
                _query_poc_by_cve, cve_id, 5,
            )
            for cve_id in plan.poc_cve_lookups
        ]

        all_futures = malware_futures + poc_futures + cti_futures + cve_futures
        results = await asyncio.gather(*all_futures, return_exceptions=True)

        # Split results back by type
        n_m = len(malware_futures)
        n_p = len(poc_futures)
        n_c = len(cti_futures)

        malware_raw = results[:n_m]
        poc_raw = results[n_m:n_m + n_p]
        cti_raw = results[n_m + n_p:n_m + n_p + n_c]
        cve_raw = results[n_m + n_p + n_c:]

        # Parse + deduplicate
        all_techniques = _dedup_techniques([
            t for raw in malware_raw if not isinstance(raw, Exception)
            for t in _parse_malware_results(raw)
        ])
        all_pocs = _dedup_pocs([
            p for raw in poc_raw if not isinstance(raw, Exception)
            for p in _parse_poc_semantic(raw)
        ])
        all_cti = _dedup_cti([
            f for raw in cti_raw if not isinstance(raw, Exception)
            for f in _parse_cti_results(raw)
        ])
        all_cve_pocs = _dedup_pocs([
            p for raw in cve_raw if not isinstance(raw, Exception)
            for p in _parse_poc_cve_lookup(raw)
        ])

        # Extract CVEs mentioned in CTI findings → do follow-up CVE lookups
        cti_cves = set()
        for f in all_cti:
            for cve in f.related_cves:
                if _CVE_PAT.match(cve):
                    cti_cves.add(cve.upper())
        existing_cves = {p.cve.upper() for p in all_pocs + all_cve_pocs if p.cve}
        new_cves = cti_cves - existing_cves
        if new_cves:
            logger.info("CTI cross-ref: %d new CVEs to look up", len(new_cves))
            followup = await asyncio.gather(*[
                loop.run_in_executor(self._executor, _query_poc_by_cve, cve, 3)
                for cve in list(new_cves)[:10]
            ], return_exceptions=True)
            for raw in followup:
                if not isinstance(raw, Exception):
                    all_cve_pocs.extend(_parse_poc_cve_lookup(raw))
            all_cve_pocs = _dedup_pocs(all_cve_pocs)

        # Log errors
        for i, r in enumerate(results):
            if isinstance(r, Exception):
                logger.warning("Query %d failed: %s", i, r)

        result = QueryResult(
            malware_techniques=all_techniques,
            poc_results=all_pocs,
            cti_findings=all_cti,
            cve_pocs=all_cve_pocs,
        )

        self._cache[plan.cache_key] = result

        try:
            import json as _json
            from dataclasses import asdict
            disk_path = self._disk_cache_dir / f"{plan.cache_key}.json"
            disk_path.write_text(_json.dumps(asdict(result), default=str))
            logger.debug("DB query result cached to disk: %s", disk_path)
        except Exception as exc:
            logger.warning("Disk cache write failed: %s", exc)

        logger.info("DB query complete: %d techniques, %d pocs, %d cti, %d cve_pocs (cache key %s)",
                     len(all_techniques), len(all_pocs), len(all_cti),
                     len(all_cve_pocs), plan.cache_key)
        return result

    # -- legacy compat methods (used by evasion/exploit selectors) ----------

    def query_all(self, query: str, n_results: int = 10) -> QueryResult:
        """Synchronous fallback — wraps query_unified with a temp event loop."""
        raise NotImplementedError(
            "query_all() is deprecated. Use 'await query_unified(target_spec)' instead. "
            "The generation engine should call query_unified directly."
        )

    def query_malware_by_edr(self, edr_list: List[str], n_results: int = 5) -> List[MalwareTechnique]:
        """Sync EDR query — used by EvasionSelector."""
        all_techniques = []
        for edr in edr_list:
            if not edr:
                continue
            raw = _query_malware_semantic(
                f"{edr} evasion bypass",
                n_results,
                {"edr_tags": {"$eq": edr}},
            )
            all_techniques.extend(_parse_malware_results(raw))
        return _dedup_techniques(all_techniques)

    def query_poc_by_cve(self, cve_list: List[str], n_results: int = 5) -> List[PoC]:
        """Sync CVE lookup — used by ExploitSelector."""
        all_pocs = []
        for cve in cve_list:
            if _CVE_PAT.match(cve):
                items = _query_poc_by_cve(cve, n_results)
                all_pocs.extend(_parse_poc_cve_lookup(items))
            else:
                raw = _query_poc_semantic(cve, n_results, None)
                all_pocs.extend(_parse_poc_semantic(raw))
        return _dedup_pocs(all_pocs)

    def query_findings_recent(self, days: int = 7, n_results: int = 10) -> List[CTIFinding]:
        """Sync CTI query."""
        raw = _query_cti_semantic("recent vulnerability exploit", n_results, 0.7)
        return _parse_cti_results(raw)


# ---------------------------------------------------------------------------
# Deduplication helpers
# ---------------------------------------------------------------------------

def _dedup_techniques(items: List[MalwareTechnique]) -> List[MalwareTechnique]:
    seen: Set[str] = set()
    unique = []
    for t in items:
        if t.id not in seen:
            seen.add(t.id)
            unique.append(t)
    unique.sort(key=lambda t: t.similarity, reverse=True)
    return unique


def _dedup_pocs(items: List[PoC]) -> List[PoC]:
    seen: Set[str] = set()
    unique = []
    for p in items:
        key = p.cve.upper() if p.cve else p.id
        if key not in seen:
            seen.add(key)
            unique.append(p)
    unique.sort(key=lambda p: (p.stars, p.has_usable_code), reverse=True)
    return unique


def _dedup_cti(items: List[CTIFinding]) -> List[CTIFinding]:
    seen: Set[str] = set()
    unique = []
    for f in items:
        key = f.id or f.description[:80]
        if key not in seen:
            seen.add(key)
            unique.append(f)
    unique.sort(key=lambda f: f.similarity, reverse=True)
    return unique
