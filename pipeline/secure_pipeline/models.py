"""Data model of the collector (stage 3).

SourceItem  — one message from one source (normalised, untrusted text kept as plain text).
Event       — one real-world event with a stable ID, built from one or more SourceItems.
Revision    — a significant change of an Event (drives notifications later).
SourceState — per-source cursor / conditional-GET / health state.

Internal events live in the state store; the site only sees data/events/*.json written by the
publishing step (stage 4) once texts and translations exist.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal, Optional

from pydantic import BaseModel, Field

Category = Literal["vulnerability", "attack", "update-issue"]
Severity = Literal["critical", "high", "medium", "low", "info"]
ItemKind = Literal["advisory", "kev", "notice", "regression", "announcement", "article"]
SourceKind = Literal["vendor", "kev", "nvd", "cert", "research", "media", "community"]


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


class Identifiers(BaseModel):
    cve: list[str] = Field(default_factory=list)
    advisory: list[str] = Field(default_factory=list)
    kb: list[str] = Field(default_factory=list)

    def keys(self) -> set[str]:
        return {*self.cve, *self.advisory, *self.kb}

    def merge(self, other: "Identifiers") -> bool:
        changed = False
        for f in ("cve", "advisory", "kb"):
            cur: list[str] = getattr(self, f)
            for x in getattr(other, f):
                if x not in cur:
                    cur.append(x)
                    changed = True
            cur.sort()
        return changed


class Cvss(BaseModel):
    score: float
    version: str
    source: str
    vector: Optional[str] = None


class SourceItem(BaseModel):
    source_id: str
    key: str  # stable per source (guid, advisory id, CVE …)
    kind: ItemKind
    url: str
    title: str
    summary: str = ""
    published: Optional[datetime] = None
    updated: Optional[datetime] = None
    fetched_at: datetime = Field(default_factory=utcnow)
    vendor_hint: Optional[str] = None
    product_hints: list[str] = Field(default_factory=list)
    identifiers: Identifiers = Field(default_factory=Identifiers)
    severity: Optional[Severity] = None
    cvss: Optional[Cvss] = None
    exploited: Optional[bool] = None
    ransomware: Optional[bool] = None
    fix_available: Optional[bool] = None
    kev_added: Optional[str] = None  # YYYY-MM-DD
    checksum: str = ""  # of the normalised content, detects updates of the same key


class SourceRef(BaseModel):
    source_id: str
    item_key: str
    url: str
    title: str
    publisher: str
    kind: SourceKind
    date: Optional[str] = None  # YYYY-MM-DD


class Revision(BaseModel):
    date: datetime
    kind: Literal["created", "exploitation", "fix", "versions", "workaround", "status", "edit", "source"]
    facts: dict[str, object] = Field(default_factory=dict)
    source: Optional[str] = None  # "source_id:item_key"


class Event(BaseModel):
    id: str
    category: Category
    priority: Severity
    confirmation: Literal["vendor", "official", "preliminary"]
    lifecycle: Literal["detected", "confirmed", "fix-available", "resolved"]
    fix: Literal["available", "partial", "none", "n/a", "unknown"] = "unknown"
    vendor: str
    products: list[str] = Field(default_factory=list)  # catalog ids where known
    product_names: list[str] = Field(default_factory=list)  # raw names from sources
    identifiers: Identifiers = Field(default_factory=Identifiers)
    severity: Optional[Severity] = None
    cvss: Optional[Cvss] = None
    exploited: bool = False
    kev: bool = False
    kev_added: Optional[str] = None
    ransomware: bool = False
    title_hint: str  # first source title; the article title comes from stage 4
    summary_hint: str = ""
    created_at: datetime
    updated_at: datetime
    event_date: datetime
    sources: list[SourceRef] = Field(default_factory=list)
    revisions: list[Revision] = Field(default_factory=list)
    related: list[str] = Field(default_factory=list)  # e.g. older event of the same CVE
    reason: str = ""  # why it is newsworthy
    # Source texts by "source_id:item_key" (plain, untrusted); input of the AI step.
    texts: dict[str, str] = Field(default_factory=dict)
    publish_state: Literal["pending", "published", "quarantined", "withdrawn", "skipped"] = "pending"
    ai: "AiState" = Field(default_factory=lambda: AiState())


class AiState(BaseModel):
    """Stage 4 state of one event: generated texts, retry queue, publication."""

    input_hash: Optional[str] = None  # facts + texts + prompt version the current texts were made from
    texts: dict[str, dict] = Field(default_factory=dict)  # lang -> article fields (validated)
    affected: list[dict] = Field(default_factory=list)  # grounded product/version rows
    workaround: bool = False
    model: Optional[str] = None
    prompt: Optional[str] = None
    generated_at: Optional[datetime] = None
    slugs: dict[str, str] = Field(default_factory=dict)  # frozen on first publication
    published_at: Optional[datetime] = None
    attempts: int = 0
    failed_hash: Optional[str] = None  # input that exhausted its attempts: not retried until the input changes
    last_error: Optional[str] = None
    next_try: Optional[datetime] = None
    calls: int = 0  # model calls spent on this event (all attempts)


Event.model_rebuild()


class SourceConfig(BaseModel):
    """Entry of data/sources.json (the public catalog) plus collector fields."""

    id: str
    name: str
    url: str
    kind: SourceKind
    format: str
    vendors: list[str] = Field(default_factory=list)
    interval: str = "30m"
    state: str = "planned"
    adapter: Optional[str] = None
    feed: Optional[str] = None
    # Hosts whose advisory pages may be fetched for details (affected/fixed versions) by the AI step.
    detail: list[str] = Field(default_factory=list)
    terms: Optional[str] = None

    def interval_seconds(self) -> int:
        n, unit = int(self.interval[:-1]), self.interval[-1]
        return n * {"m": 60, "h": 3600, "d": 86400}[unit]


class SourceState(BaseModel):
    id: str
    etag: Optional[str] = None
    last_modified: Optional[str] = None
    checksum: Optional[str] = None
    cursor: dict[str, str] = Field(default_factory=dict)  # adapter-specific watermarks
    seen: dict[str, str] = Field(default_factory=dict)  # item key -> checksum
    last_attempt: Optional[datetime] = None
    last_success: Optional[datetime] = None
    last_error: Optional[str] = None
    consecutive_failures: int = 0
    bootstrapped: bool = False
    items_total: int = 0
