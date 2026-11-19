"""Deduplication and event building.

Separates: source message (SourceItem) → event (Event) → per-language publication (stage 4).

Matching keys: CVE, advisory ID, KB (+ vendor and title similarity for items without IDs) within a
time window. A KEV entry for a CVE whose event is older than the window starts a *new* event
(exploitation of an old vulnerability is news of its own) linked via `related`.

Only significant changes become revisions that may notify: created, exploitation, fix, status.

A later revision of the same source message always returns to its event (matched by source reference).
Update issues (regressions) and vulnerabilities never merge with each other: a KB is shared by the
vulnerabilities it fixes and by unrelated issues it causes.

Secondary sources (CERT, researchers, media, community) add context to vendor events but never change
their facts (identifiers, severity, exploitation, fix); a secondary item opens an event only with a CVE
to deduplicate against, and not when it bundles many CVEs (e.g. a CERT summary of a kernel update).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional

from .models import Event, Identifiers, Revision, SourceConfig, SourceItem, SourceRef
from .store import Store, ref_key
from .text import similarity

WINDOW = timedelta(days=120)
MAX_TEXTS = 8
TEXT_LIMIT = 2500
TITLE_WINDOW = timedelta(days=14)
STALE = timedelta(days=30)  # older messages open events only for exploitation (e.g. an old advisory edited today)
BUNDLE = 25  # CVEs in one secondary message above which it is a roundup, not one event
SECONDARY = {"cert", "research", "media", "community"}
REPORTER = {"cert": "CERT reports", "research": "researchers report", "media": "media report", "community": "community reports"}
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


def newsworthy(it: SourceItem, products: list[str], source_kind: Optional[str] = None,
               now: Optional[datetime] = None) -> Optional[str]:
    """Why an item may open a new event, or None.

    Infrastructure focus, not a full CVE catalog: exploitation always counts; otherwise only critical
    issues (CVSS >= 9 where a score exists) in catalog products or perimeter-type software.
    Distro notices and announcements never open events — they only add fix information.
    Messages first published more than STALE ago (an old advisory edited today) only count for exploitation.
    """
    if it.kind in ("notice", "announcement"):
        return None
    if it.kind == "kev":
        return "added to CISA KEV"
    # Secondary sources: a catalog product (names the vendor) and a CVE to deduplicate against.
    if source_kind in SECONDARY and (not products or not 0 < len(it.identifiers.cve) <= BUNDLE):
        return None
    stale = bool(now and it.published and now - it.published > STALE)
    if it.kind == "regression":
        return None if stale else "update regression"
    if it.exploited:
        return f"{REPORTER.get(source_kind or '', 'vendor reports')} exploitation"
    if stale:
        return None
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
        src = self.catalog.sources.get(it.source_id)
        same = self.store.events_for_keys([ref_key(it.source_id, it.key)])
        if same:
            return self._merge(max(same, key=lambda e: e.created_at), it)
        keys = it.identifiers.keys()
        regression = it.kind == "regression"
        # A KB alone never links update issues: one cumulative update can cause several unrelated ones.
        cands = [] if regression else self._by_ids(it)
        if not cands and it.kind != "notice" and (regression or not keys) and not (src and src.kind in SECONDARY):
            cands = self._by_title(it)
        if cands:
            # Most shared identifiers first, then the newest event.
            best = max(cands, key=lambda e: (len(e.identifiers.keys() & keys), e.created_at))
            return self._merge(best, it)
        products = self.catalog.match_products(it.vendor_hint, *it.product_hints, it.title, it.summary[:400])
        reason = newsworthy(it, products, src.kind if src else None, self.now)
        if not reason:
            return Outcome("ignored")
        older = [] if regression else self._kin(it, self.store.events_for_keys(keys))
        return self._create(it, reason, related=[e.id for e in older])

    def _by_ids(self, it: SourceItem) -> list[Event]:
        """Strongest shared identifier first: CVE, then advisory, then KB — the KB only for items without a CVE.

        One cumulative update (KB) fixes dozens of unrelated CVEs: two CVEs must not merge through it.
        """
        ids = it.identifiers
        for group in (ids.cve, ids.advisory, [] if ids.cve else ids.kb):
            found = [e for e in self._kin(it, self.store.events_for_keys(group)) if self.now - e.created_at <= WINDOW]
            if found:
                return found
        return []

    @staticmethod
    def _kin(it: SourceItem, events: list[Event]) -> list[Event]:
        """Events of the same kind: update issues and vulnerabilities never merge."""
        issue = it.kind == "regression"
        return [e for e in events if (e.category == "update-issue") == issue]

    def _by_title(self, it: SourceItem) -> list[Event]:
        out = []
        for e in self._kin(it, list(self.store.events.values())):
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
        vendor = it.vendor_hint or (src.vendors[0] if src and src.vendors else None)
        if not vendor:  # multi-vendor sources (CERT, researchers): the matched catalog product names it
            vendor = next((p["vendor"] for p in self.catalog.products if p["id"] in products and p.get("vendor")), "unknown")
        e = Event(
            id=self.store.next_event_id(self.now.year),
            category="update-issue" if it.kind == "regression" else "vulnerability",
            priority="low", confirmation=_confirmation(src), lifecycle="confirmed",
            fix="available" if it.fix_available else "unknown",
            vendor=vendor,
            products=products, product_names=[p for p in it.product_hints if p],
            identifiers=it.identifiers.model_copy(deep=True), severity=it.severity or _sev_from_cvss(it), cvss=it.cvss,
            exploited=bool(it.exploited), kev=it.kind == "kev", kev_added=it.kev_added, ransomware=bool(it.ransomware),
            title_hint=it.title, summary_hint=it.summary[:1500],
            created_at=self.now, updated_at=self.now, event_date=when,
            sources=[_ref(it, src)], related=related, reason=reason,
            texts={f"{it.source_id}:{it.key}": _text(it)},
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
        # A secondary source only adds context to an event it did not open: its facts may cover a bundle
        # of products, and its wording about exploitation is not a vendor statement.
        context_only = bool(src and src.kind in SECONDARY) and not (e.revisions and e.revisions[0].source == tag)

        changed = False
        if not any(s.source_id == it.source_id and s.item_key == it.key for s in e.sources):
            e.sources.append(_ref(it, src))
            changed = True
        if e.identifiers.merge(Identifiers(advisory=it.identifiers.advisory) if context_only else it.identifiers):
            changed = True
        text = _text(it)
        relevant_text = not context_only or len(it.identifiers.cve) <= 3  # a bundle's text is noise for this event
        if relevant_text and e.texts.get(tag) != text and (tag in e.texts or len(e.texts) < MAX_TEXTS):
            e.texts[tag] = text
            changed = True
        if context_only:
            if src.kind == "cert" and e.confirmation == "preliminary":
                e.confirmation = "official"
                kinds.append("status")
            return self._finish(e, tag, kinds, changed, before_priority)
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
        return self._finish(e, tag, kinds, changed, before_priority)

    def _finish(self, e: Event, tag: str, kinds: list[str], changed: bool, before_priority: str) -> Outcome:
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


def _text(it: SourceItem) -> str:
    return f"{it.title}\n{it.summary}".strip()[:TEXT_LIMIT]


def _ref(it: SourceItem, src: Optional[SourceConfig]) -> SourceRef:
    return SourceRef(
        source_id=it.source_id, item_key=it.key, url=it.url, title=it.title[:300],
        publisher=src.name if src else it.source_id, kind=src.kind if src else "media",
        date=(it.published or it.fetched_at).strftime("%Y-%m-%d"),
    )
