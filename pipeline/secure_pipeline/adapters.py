"""Source adapters. Each turns one fetched source into normalised SourceItems.

Adapters never decide what is newsworthy — clustering does. They return None when the source
did not change since the last successful run (304 / same checksum / no new documents).
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional
from urllib.parse import quote

import feedparser

from .fetch import Fetcher, FetchError
from .models import Cvss, Identifiers, ItemKind, SourceConfig, SourceItem, SourceState, utcnow
from .text import checksum, identifiers, parse_date, plain, severity_from_score, severity_word

Adapter = Callable[[SourceConfig, SourceState, Fetcher], Optional[list[SourceItem]]]
REGISTRY: dict[str, Adapter] = {}


def adapter(name: str):
    def deco(fn: Adapter) -> Adapter:
        REGISTRY[name] = fn
        return fn

    return deco


def _conditional(src: SourceConfig, state: SourceState, fetch: Fetcher, **kw):
    """GET with ETag/Last-Modified; returns (response, changed)."""
    r = fetch.get(src.feed or src.url, etag=state.etag, last_modified=state.last_modified, **kw)
    if r.not_modified:
        return r, False
    cs = r.checksum()
    changed = cs != state.checksum
    state.etag, state.last_modified, state.checksum = r.etag, r.last_modified, cs
    return r, changed


# ---------------------------------------------------------------- CISA KEV

@adapter("cisa_kev")
def cisa_kev(src: SourceConfig, state: SourceState, fetch: Fetcher):
    r, changed = _conditional(src, state, fetch)
    if not changed:
        return None
    data = json.loads(r.body)
    state.cursor["catalogVersion"] = str(data.get("catalogVersion", ""))
    items = []
    for v in data.get("vulnerabilities", []):
        cve = str(v.get("cveID", "")).upper()
        if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve):
            continue
        ransomware = str(v.get("knownRansomwareCampaignUse", "")).lower() == "known"
        summary = plain(v.get("shortDescription"))
        action = plain(v.get("requiredAction"), 600)
        items.append(SourceItem(
            source_id=src.id, key=cve, kind="kev",
            url=f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={quote(cve)}",
            title=plain(v.get("vulnerabilityName"), 300) or cve,
            summary=f"{summary}\n\nRequired action: {action}" if action else summary,
            published=parse_date(v.get("dateAdded")),
            vendor_hint=plain(v.get("vendorProject"), 120), product_hints=[plain(v.get("product"), 120)],
            identifiers=Identifiers(cve=[cve]), exploited=True, ransomware=ransomware,
            kev_added=str(v.get("dateAdded", ""))[:10] or None,
            checksum=checksum(v.get("dateAdded"), v.get("knownRansomwareCampaignUse"), v.get("requiredAction"), v.get("dueDate")),
        ))
    return items


# ---------------------------------------------------------------- RSS / Atom / RDF

SEV_PATTERNS = [
    re.compile(r"Severity:\s*(Critical|High|Medium|Moderate|Low|Informational)", re.I),
    re.compile(r"Security Impact Rating:\s*(Critical|High|Medium|Low|Informational)", re.I),
]
SCORE_PATTERNS = [
    re.compile(r"CVSS\s*v?3(?:\.\d)?\s*(?:Base\s*)?Score:\s*([\d.]+)", re.I),
    re.compile(r"CVSS\s*(?:Base\s*)?Score:\s*([\d.]+)", re.I),
    re.compile(r"CVSS Rating:\s*\**([\d.]+)\**", re.I),
]
EXPLOITED_RE = re.compile(
    r"(exploited in the wild|actively exploited|active exploitation|is aware of (?:attempted )?exploitation"
    r"|has been exploited|have been exploited|known to be exploited|exploitation (?:has been|was) observed"
    r"|observed (?:attempted )?exploitation)", re.I)
NOT_EXPLOITED_RE = re.compile(r"(not aware of any (?:malicious use|exploitation|public)|no known exploitation)", re.I)

FEED_KIND: dict[str, ItemKind] = {
    "ubuntu-usn": "notice", "debian-dsa": "notice",
    "proxmox-announcements": "announcement", "opnsense-releases": "announcement",
}


def _severity_and_score(text: str):
    score = None
    for p in SCORE_PATTERNS:
        m = p.search(text)
        if m:
            try:
                score = float(m.group(1).rstrip("."))
                break
            except ValueError:
                pass
    sev = None
    for p in SEV_PATTERNS:
        m = p.search(text)
        if m:
            sev = severity_word(m.group(1))
            break
    return sev or severity_from_score(score), score


@adapter("rss")
def rss(src: SourceConfig, state: SourceState, fetch: Fetcher):
    r, changed = _conditional(src, state, fetch)
    if not changed:
        return None
    feed = feedparser.parse(r.body)
    if feed.bozo and not feed.entries:
        raise FetchError(f"unparseable feed: {type(feed.bozo_exception).__name__}")
    items = []
    for e in feed.entries[:200]:
        link = str(e.get("link") or "")
        key = str(e.get("id") or link or e.get("title") or "")[:300]
        if not key:
            continue
        raw = e.get("summary") or ""
        if e.get("content"):
            raw = e["content"][0].get("value") or raw
        title = plain(e.get("title"), 300)
        summary = plain(raw)
        sev, score = _severity_and_score(f"{title}\n{summary}")
        exploited = True if EXPLOITED_RE.search(summary) and not NOT_EXPLOITED_RE.search(summary) else None
        published = parse_date(e.get("published") or e.get("updated") or e.get("dc_date"))
        items.append(SourceItem(
            source_id=src.id, key=key, kind=FEED_KIND.get(src.id, "advisory"),
            url=link or src.url, title=title or key, summary=summary,
            published=published, updated=parse_date(e.get("updated")),
            vendor_hint=src.vendors[0] if src.vendors else None,
            identifiers=identifiers(title, summary, link),
            severity=sev, cvss=Cvss(score=score, version="3.x", source=src.name) if score is not None else None,
            exploited=exploited, fix_available=True if FEED_KIND.get(src.id) == "notice" else None,
            checksum=checksum(title, summary, published),
        ))
    return items


# ---------------------------------------------------------------- JSON Feed (Kubernetes official CVE feed)

K8S_RATING = re.compile(r"CVSS Rating:\s*\**([\d.]+)\**\s*\((\w+)\)", re.I)


@adapter("jsonfeed")
def jsonfeed(src: SourceConfig, state: SourceState, fetch: Fetcher):
    r, changed = _conditional(src, state, fetch)
    if not changed:
        return None
    data = json.loads(r.body)
    items = []
    for it in data.get("items", [])[:500]:
        text = plain(it.get("content_text") or it.get("summary"))
        m = K8S_RATING.search(text)
        score = float(m.group(1)) if m else None
        key = str(it.get("id") or it.get("url"))
        title = plain(it.get("title") or key, 300)
        items.append(SourceItem(
            source_id=src.id, key=key, kind="advisory", url=str(it.get("url") or src.url),
            title=title, summary=text, published=parse_date(it.get("date_published")),
            vendor_hint="Kubernetes", identifiers=identifiers(key, title, text),
            severity=severity_word(m.group(2)) if m else severity_from_score(score),
            cvss=Cvss(score=score, version="3.1", source="Kubernetes") if score is not None else None,
            checksum=checksum(title, text),
        ))
    return items


# ---------------------------------------------------------------- Red Hat Security Data API

@adapter("redhat")
def redhat(src: SourceConfig, state: SourceState, fetch: Fetcher):
    after = state.cursor.get("after") or (utcnow() - timedelta(days=14)).strftime("%Y-%m-%d")
    base = src.feed or "https://access.redhat.com/hydra/rest/securitydata/cve.json"
    items, newest = [], after
    for sev in ("critical", "important"):
        r = fetch.get(f"{base}?after={after}&severity={sev}&per_page=200")
        for v in json.loads(r.body) or []:
            cve = str(v.get("CVE", "")).upper()
            if not cve.startswith("CVE-"):
                continue
            desc = plain(v.get("bugzilla_description"), 400)
            product = desc.split(":", 1)[0].strip() if ":" in desc else ""
            score = v.get("cvss3_score")
            try:
                score = float(score) if score not in (None, "") else None
            except ValueError:
                score = None
            pub = parse_date(v.get("public_date"))
            if pub and pub.strftime("%Y-%m-%d") > newest:
                newest = pub.strftime("%Y-%m-%d")
            advisories = [a for a in v.get("advisories") or [] if isinstance(a, str)]
            items.append(SourceItem(
                source_id=src.id, key=cve, kind="advisory",
                url=f"https://access.redhat.com/security/cve/{cve.lower()}", title=desc or cve,
                summary=desc, published=pub, vendor_hint="Red Hat", product_hints=[product] if product else [],
                identifiers=Identifiers(cve=[cve], advisory=sorted(advisories)),
                severity=severity_word(v.get("severity")),
                cvss=Cvss(score=score, version="3.x", source="Red Hat") if score is not None else None,
                fix_available=bool(advisories) or None,
                checksum=checksum(desc, v.get("severity"), sorted(advisories), score),
            ))
    # Overlap by two days so late edits are seen again; seen-checksums prevent duplicates.
    state.cursor["after"] = (datetime.fromisoformat(newest) - timedelta(days=2)).strftime("%Y-%m-%d")
    return items


# ---------------------------------------------------------------- Microsoft Security Response Center (CVRF)

SKIP_TAGS = re.compile(r"mariner|azure linux|cbl", re.I)


@adapter("msrc")
def msrc(src: SourceConfig, state: SourceState, fetch: Fetcher):
    r, changed = _conditional(src, state, fetch, headers={"Accept": "application/json"})
    if not changed:
        return None
    updates = json.loads(r.body).get("value", [])
    horizon = (utcnow() - timedelta(days=45)).isoformat()
    items: list[SourceItem] = []
    any_doc = False
    for u in updates:
        doc_id, current = u.get("ID"), str(u.get("CurrentReleaseDate") or "")
        if not doc_id or "Security Updates" not in str(u.get("DocumentTitle", "")):
            continue
        if current < horizon or state.cursor.get(f"doc:{doc_id}") == current:
            continue
        doc = json.loads(fetch.get(u["CvrfUrl"], headers={"Accept": "application/json"}).body)
        any_doc = True
        state.cursor[f"doc:{doc_id}"] = current
        items.extend(_cvrf_items(src, doc, doc_id))
    return items if any_doc else None


def _cvrf_items(src: SourceConfig, doc: dict, doc_id: str) -> list[SourceItem]:
    names = {p.get("ProductID"): p.get("Value") for p in doc.get("ProductTree", {}).get("FullProductName", [])}
    out = []
    for v in doc.get("Vulnerability", []):
        cve = str(v.get("CVE", "")).upper()
        tags = " ".join(str(n.get("Value", "")) for n in v.get("Notes", []) if n.get("Type") == 7)
        if not cve.startswith("CVE-") or SKIP_TAGS.search(tags):
            continue
        exploit_status = " ".join(str(t.get("Description", {}).get("Value", "")) for t in v.get("Threats", []) if t.get("Type") == 1)
        sevs = [severity_word(t.get("Description", {}).get("Value")) for t in v.get("Threats", []) if t.get("Type") == 3]
        order = ["info", "low", "medium", "high", "critical"]
        sev = max((s for s in sevs if s), key=order.index, default=None)
        kbs = sorted({f"KB{d}" for rem in v.get("Remediations", []) if rem.get("Type") == 2
                      for d in re.findall(r"\b(\d{6,8})\b", str(rem.get("Description", {}).get("Value", "")))})
        scores = [s.get("BaseScore") for s in v.get("CVSSScoreSets", []) if isinstance(s.get("BaseScore"), (int, float))]
        product_ids = {pid for st in v.get("ProductStatuses", []) for pid in st.get("ProductID", [])}
        products = sorted({names[p] for p in product_ids if p in names})[:12]
        title = plain((v.get("Title") or {}).get("Value"), 300) or cve
        exploited = "Exploited:Yes" in exploit_status
        disclosed = "Publicly Disclosed:Yes" in exploit_status
        out.append(SourceItem(
            source_id=src.id, key=cve, kind="advisory",
            url=f"https://msrc.microsoft.com/update-guide/vulnerability/{cve}",
            title=f"{title}", summary=f"{tags}. {'Publicly disclosed. ' if disclosed else ''}Microsoft {doc_id} security update.".strip(),
            published=parse_date(v.get("ReleaseDate")) if v.get("ReleaseDateSpecified") else None,
            vendor_hint="Microsoft", product_hints=products,
            identifiers=Identifiers(cve=[cve], kb=kbs), severity=sev,
            cvss=Cvss(score=max(scores), version="3.1", source="Microsoft") if scores else None,
            exploited=True if exploited else None, fix_available=bool(kbs) or None,
            checksum=checksum(title, exploit_status, sev, kbs, max(scores) if scores else None),
        ))
    return out


# ---------------------------------------------------------------- NVD (enrichment only, not an event source)

def nvd_lookup(fetch: Fetcher, cve: str, api_key: Optional[str] = None) -> Optional[dict]:
    headers = {"apiKey": api_key} if api_key else None
    r = fetch.get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={quote(cve)}", headers=headers)
    vulns = json.loads(r.body).get("vulnerabilities", [])
    if not vulns:
        return None
    c = vulns[0]["cve"]
    desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
    cvss = None
    for key, ver in (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0")):
        metrics = c.get("metrics", {}).get(key) or []
        primary = next((m for m in metrics if m.get("type") == "Primary"), metrics[0] if metrics else None)
        if primary:
            d = primary["cvssData"]
            cvss = {"score": d.get("baseScore"), "version": ver, "vector": d.get("vectorString"), "source": primary.get("source", "NVD")}
            break
    return {"description": plain(desc), "cvss": cvss, "published": c.get("published"), "lastModified": c.get("lastModified")}
