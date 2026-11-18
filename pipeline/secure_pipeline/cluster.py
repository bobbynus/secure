"""Deduplication and event building.

Separates: source message (SourceItem) → event (Event) → per-language publication (stage 4).

Matching keys: CVE, advisory ID, KB (+ vendor and title similarity for items without IDs) within a
time window. A KEV entry for a CVE whose event is older than the window starts a *new* event
(exploitation of an old vulnerability is news of its own) linked via `related`.

Only significant changes become revisions that may notify: created, exploitation, fix, status.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional

from .models import Event, Revision, SourceConfig, SourceItem, SourceRef
from .store import Store
from .text import similarity

WINDOW = timedelta(days=120)
TITLE_WINDOW = timedelta(days=14)
ORDER = ["info", "low", "medium", "high", "critical"]
PERIMETER = {"panos", "fortios", "fortiproxy", "ivanti-connect-secure", "ivanti-policy-secure", "cisco-asa",
             "cisco-ftd", "netscaler-adc", "netscaler-gateway", "esxi", "vcenter-server", "exchange-server",
             "cisco-ios-xe", "fortimanager", "fortiweb"}
PERIMETER_RE = re.compile(r"\b(vpn|ssl ?vpn|firewall|gateway|edge|remote access|load balancer|hypervisor)\b", re.I)


@dataclass
class Catalog:
    sources: dict[str, SourceConfig]
    products: list[dict]

    def __post_init__(self):
        # Whole-word patterns: "runc" must not match "truncation".
        self._patterns = [
            (p["id"], re.compile(r"(?<![a-z0-9])" + re.escape(m.strip().lower()) + r"(?![a-z0-9])"))
            for p in self.products for m in p.get("match", []) if m.strip()
        ]

    def match_products(self, *texts: Optional[str]) -> list[str]:
        hay = " ".join(t.lower() for t in texts if t)
        return sorted({pid for pid, rx in self._patterns if rx.search(hay)})


@dataclass
class Outcome:
    action: str  # created | updated | unchanged | ignored | baseline
    event_id: Optional[str] = None
    revisions: tuple[str, ...] = ()


def newsworthy(it: SourceItem, products: list[str]) -> Optional[str]:
    """Why an item may open a new event, or None.

    Infrastructure focus, not a full CVE catalog: exploitation always counts; otherwise only critical
    issues (CVSS >= 9 where a score exists) in catalog products or perimeter-type software.
    Distro notices and announcements never open events — they only add fix information.
    """
    if it.kind in ("notice", "announcement"):
        return None
    if it.kind == "kev":
        return "added to CISA KEV"
    if it.kind == "regression":
        return "update regression"
    if it.exploited:
        return "vendor reports exploitation"
    sev = it.severity or _sev_from_cvss(it)
    if sev != "critical" or (it.cvss and it.cvss.score is not None and it.cvss.score < 9.0):
        return None
    if products or PERIMETER_RE.search(" ".join([it.title, *it.product_hints])):
        return "critical severity in infrastructure product"
    return None


def _sev_from_cvss(it: SourceItem):
    if it.cvss and it.cvss.score is not None:
        s = it.cvss.score
        return "critical" if s >= 9 else "high" if s >= 7 else "medium" if s >= 4 else "low"
    return None


def editorial_priority(e: Event) -> str:
    sev = e.severity or (("critical" if e.cvss.score >= 9 else "high" if e.cvss.score >= 7 else "medium" if e.cvss.score >= 4 else "low") if e.cvss else None)
    perimeter = bool(set(e.products) & PERIMETER) or bool(PERIMETER_RE.search(" ".join(e.product_names + [e.title_hint])))
    if e.exploited and (sev == "critical" or e.ransomware or perimeter):
        return "critical"
    if e.exploited:
        return "high"
    if sev == "critical":
        return "high"
    if sev == "high":
        return "medium"
    if e.category == "update-issue":
        return "medium"
    return "low"


class Clusterer:
    def __init__(self, store: Store, catalog: Catalog, now: datetime):
        self.store, self.catalog, self.now = store, catalog, now

    def process(self, it: SourceItem) -> Outcome:
        keys = it.identifiers.keys()
        cands = [e for e in self.store.events_for_keys(keys) if self.now - e.created_at <= WINDOW]
        if not cands and not keys and it.kind != "notice":
            cands = self._by_title(it)
        if cands:
            # Most shared identifiers first, then the newest event.
            best = max(cands, key=lambda e: (len(e.identifiers.keys() & keys), e.created_at))
            return self._merge(best, it)
        reason = newsworthy(it, self.catalog.match_products(it.vendor_hint, *it.product_hints, it.title, it.summary[:400]))
        if not reason:
            return Outcome("ignored")
        older = self.store.events_for_keys(keys)
        return self._create(it, reason, related=[e.id for e in older])

    def _by_title(self, it: SourceItem) -> list[Event]:
        out = []
        for e in self.store.events.values():
            if self.now - e.created_at > TITLE_WINDOW:
                continue
            if it.vendor_hint and e.vendor.lower() != it.vendor_hint.lower():
                continue
            if similarity(e.title_hint, it.title) >= 0.6:
                out.append(e)
        return out

    # ------------------------------------------------------------ create

    def _create(self, it: SourceItem, reason: str, related: list[str]) -> Outcome:
        when = it.published or self.now
        src = self.catalog.sources.get(it.source_id)
        products = self.catalog.match_products(it.vendor_hint, *it.product_hints, it.title, it.summary[:400])
        e = Event(
            id=self.store.next_event_id(self.now.year),
            category="update-issue" if it.kind == "regression" else "vulnerability",
            priority="low", confirmation=_confirmation(src), lifecycle="confirmed",
            fix="available" if it.fix_available else "unknown",
            vendor=it.vendor_hint or (src.vendors[0] if src and src.vendors else "unknown"),
            products=products, product_names=[p for p in it.product_hints if p],
            identifiers=it.identifiers.model_copy(deep=True), severity=it.severity or _sev_from_cvss(it), cvss=it.cvss,
            exploited=bool(it.exploited), kev=it.kind == "kev", kev_added=it.kev_added, ransomware=bool(it.ransomware),
            title_hint=it.title, summary_hint=it.summary[:1500],
            created_at=self.now, updated_at=self.now, event_date=when,
            sources=[_ref(it, src)], related=related, reason=reason,
        )
        e.lifecycle = "fix-available" if e.fix == "available" else "confirmed"
        e.priority = editorial_priority(e)
        e.revisions.append(Revision(date=self.now, kind="created", facts={"reason": reason}, source=f"{it.source_id}:{it.key}"))
        self.store.put_event(e)
        return Outcome("created", e.id, ("created",))

    # ------------------------------------------------------------ merge

    def _merge(self, e: Event, it: SourceItem) -> Outcome:
        src = self.catalog.sources.get(it.source_id)
        tag = f"{it.source_id}:{it.key}"
        kinds: list[str] = []
        before_priority = e.priority

        changed = False
        if not any(s.source_id == it.source_id and s.item_key == it.key for s in e.sources):
            e.sources.append(_ref(it, src))
            changed = True
        if e.identifiers.merge(it.identifiers):
            changed = True
        for p in self.catalog.match_products(it.vendor_hint, *it.product_hints):
            if p not in e.products:
                e.products.append(p)
                changed = True
        if e.vendor == "unknown" and it.vendor_hint:
            e.vendor = it.vendor_hint

        # Exploitation: KEV listing or vendor statement.
        if (it.exploited or it.kind == "kev") and not e.exploited:
            e.exploited = True
            kinds.append("exploitation")
        if it.kind == "kev" and not e.kev:
            e.kev, e.kev_added = True, it.kev_added
            if "exploitation" not in kinds:
                kinds.append("exploitation")
            if e.confirmation == "preliminary":
                e.confirmation = "official"
        if it.ransomware and not e.ransomware:
            e.ransomware = True
            changed = True

        # Fix availability (vendor advisory with fix, distro notices).
        if it.fix_available and e.fix in ("unknown", "none"):
            e.fix, e.lifecycle = "available", "fix-available"
            kinds.append("fix")

        sev = it.severity or _sev_from_cvss(it)
        if sev and (e.severity is None or ORDER.index(sev) > ORDER.index(e.severity)):
            e.severity = sev
            changed = True
        if it.cvss and (e.cvss is None or (it.source_id != "nvd" and e.cvss.source == "NVD")):
            e.cvss = it.cvss
            changed = True
        if src and src.kind == "vendor" and e.confirmation == "preliminary":
            e.confirmation = "vendor"
            kinds.append("status")

        e.priority = editorial_priority(e)
        if ORDER.index(e.priority) > ORDER.index(before_priority) and "status" not in kinds:
            kinds.append("status")

        for k in kinds:
            facts: dict[str, object] = {}
            if k == "exploitation":
                facts = {"kev": e.kev_added, "ransomware": e.ransomware}
            elif k == "fix":
                facts = {"kb": e.identifiers.kb, "advisories": e.identifiers.advisory}
            elif k == "status":
                facts = {"priority": e.priority, "confirmation": e.confirmation}
            e.revisions.append(Revision(date=self.now, kind=k, facts=facts, source=tag))
        if not kinds and changed:
            e.revisions.append(Revision(date=self.now, kind="source", source=tag))
        if kinds or changed:
            e.updated_at = self.now
            self.store.put_event(e)
            return Outcome("updated", e.id, tuple(kinds))
        return Outcome("unchanged", e.id)


def _confirmation(src: Optional[SourceConfig]) -> str:
    if not src:
        return "preliminary"
    if src.kind in ("kev", "cert", "nvd"):
        return "official"
    if src.kind == "vendor":
        return "vendor"
    return "preliminary"


def _ref(it: SourceItem, src: Optional[SourceConfig]) -> SourceRef:
    return SourceRef(
        source_id=it.source_id, item_key=it.key, url=it.url, title=it.title[:300],
        publisher=src.name if src else it.source_id, kind=src.kind if src else "media",
        date=(it.published or it.fetched_at).strftime("%Y-%m-%d"),
    )
