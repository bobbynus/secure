"""Source adapters. Each turns one fetched source into normalised SourceItems.

Adapters never decide what is newsworthy — clustering does. They return None when the source
did not change since the last successful run (304 / same checksum / no new documents).
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional
from urllib.parse import quote, urljoin, urlsplit

import feedparser

from .fetch import Fetcher, FetchError
from .models import Cvss, Identifiers, ItemKind, SourceConfig, SourceItem, SourceState, utcnow
from .text import CVE_RE, KB_RE, checksum, identifiers, parse_date, plain, severity_from_score, severity_word

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
    re.compile(r"CVSS rating of\s*([\d.]+)", re.I),  # ZDI
]
EXPLOITED_RE = re.compile(
    r"(exploited in the wild|actively exploited|active exploitation|is aware of (?:attempted )?exploitation"
    r"|has been exploited|have been exploited|known to be exploited|exploitation (?:has been|was) observed"
    r"|observed (?:attempted )?exploitation"
    # Media headlines: "… exploited in zero-day attacks", "Hackers exploit … flaw".
    r"|exploited (?:in|as) (?:[\w-]+ ){0,2}(?:attacks|zero-days?)"
    r"|(?:hackers|attackers|threat actors|cybercriminals|ransomware gangs?) (?:now |actively )?(?:exploit|exploiting)\b)", re.I)
NOT_EXPLOITED_RE = re.compile(
    r"(not aware of any (?:malicious use|malicious exploitation|exploitation|public)|no known exploitation"
    r"|no (?:evidence|indication|reports?) of (?:active )?exploitation)", re.I)
NEGATION_RE = re.compile(r"\b(not|no|never|without|nor|isn't|aren't|wasn't|weren't|unaware)\b[^.;:]*$", re.I)


def exploitation_claimed(text: str) -> bool:
    """True only for a positive statement: "not known to be actively exploited" is not one."""
    if NOT_EXPLOITED_RE.search(text):
        return False
    for m in EXPLOITED_RE.finditer(text):
        if not NEGATION_RE.search(text[max(0, m.start() - 60):m.start()]):
            return True
    return False

FEED_KIND: dict[str, ItemKind] = {
    "ubuntu-usn": "notice", "debian-dsa": "notice",
    "proxmox-announcements": "announcement", "opnsense-releases": "announcement",
    "bleepingcomputer": "article",
}
# Feeds that name their advisories (and CVEs) only in links, e.g. Ivanti's monthly security post.
LINK_IDS = {"ivanti-advisories"}
# Media feeds carry a teaser only: the article body (start marker … first end marker) is read once per new
# article for its CVEs. Politely: a few pages per run with a pause between them (robots.txt crawl-delay).
ARTICLE_BODY = {"bleepingcomputer": ('class="articleBody"', ("Related Articles", 'class="article_section_bottom"'))}
ARTICLES_PER_RUN = 10
ARTICLE_DELAY = 2.0


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
    own_hosts = {(urlsplit(src.feed or src.url).hostname or "").lower(), *(h.lower() for h in src.detail)}
    items = []
    articles = 0
    for e in feed.entries[:200]:
        link = str(e.get("link") or "")
        if link.startswith("http://") and (urlsplit(link).hostname or "").lower() in own_hosts:
            link = "https://" + link[len("http://"):]  # ZDI publishes http links to its https site
        key = str(e.get("id") or link or e.get("title") or "")[:300]
        if not key:
            continue
        raw = e.get("summary") or ""
        if e.get("content"):
            raw = e["content"][0].get("value") or raw
        title = plain(e.get("title"), 300)
        summary = plain(raw)
        sev, score = _severity_and_score(f"{title}\n{summary}")
        # Media headlines carry the claim ("… exploited in attacks"); vendor titles do not need it.
        exploited = True if exploitation_claimed(f"{title}.\n{summary}" if src.kind == "media" else summary) else None
        published = parse_date(e.get("published") or e.get("updated") or e.get("dc_date"))
        ids = identifiers(title, summary, link, *(_hrefs(raw) if src.id in LINK_IDS else ()))
        if src.id in ARTICLE_BODY and key not in state.seen and articles < ARTICLES_PER_RUN \
                and (urlsplit(link).hostname or "").lower() in own_hosts:
            if articles:
                fetch.sleep(ARTICLE_DELAY)
            articles += 1
            ids.merge(_article_ids(fetch, link, title, *ARTICLE_BODY[src.id]))
        items.append(SourceItem(
            source_id=src.id, key=key, kind=FEED_KIND.get(src.id, "advisory"),
            url=link or src.url, title=title or key, summary=summary,
            published=published, updated=parse_date(e.get("updated")),
            vendor_hint=src.vendors[0] if src.vendors else None,
            identifiers=ids,
            severity=sev, cvss=Cvss(score=score, version="3.x", source=src.name) if score is not None else None,
            exploited=exploited, fix_available=True if FEED_KIND.get(src.id) == "notice" else None,
            checksum=checksum(title, summary, published),
        ))
    return items


def _hrefs(raw: str) -> list[str]:
    return re.findall(r"""href=["']([^"']+)["']""", raw or "")


def _article_ids(fetch: Fetcher, url: str, title: str, start: str, ends: tuple[str, ...]) -> Identifiers:
    """CVEs an article is about: named in the title, the first one in the body, or repeated in it.

    Articles also mention older, related CVEs once ("… like the ActiveMQ flaw CVE-… last year"); those are
    context and must not link the article to another event.
    """
    try:
        page = fetch.get(url, max_bytes=3 * 1024 * 1024).text()
    except FetchError:
        return Identifiers()  # the teaser is still there; the article just stays unlinked
    i = page.find(start)
    if i < 0:
        return Identifiers()
    j = min([k for k in (page.find(end, i) for end in ends) if k > 0] or [len(page)])
    found = [m.upper() for m in CVE_RE.findall(plain(page[i:j], 60_000))]
    keep = set(identifiers(title).cve)
    if found:
        keep.add(found[0])
        keep.update(c for c in set(found) if found.count(c) >= 2)
    return Identifiers(cve=sorted(keep))


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


# ---------------------------------------------------------------- CSAF 2.0 provider (CERT-Bund WID)

CSAF_DOCS_PER_RUN = 60
CSAF_FIRST_DAYS = 2  # first contact: only documents changed in the last days (no archive download)
CSAF_DOC_BYTES = 8 * 1024 * 1024
CSAF_PATH = re.compile(r"[A-Za-z0-9_./-]+\.json")


@adapter("csaf")
def csaf(src: SourceConfig, state: SourceState, fetch: Fetcher):
    """CSAF directory: `changes.csv` (path, timestamp; newest first) → changed documents → items.

    The ROLIE index of CERT-Bund is ~50 MB; changes.csv (~1 MB, ETag) is enough to find what changed.
    At most CSAF_DOCS_PER_RUN documents per run, oldest change first; the rest is a backlog for the next run.
    """
    if state.cursor.pop("backlog", None):
        r = fetch.get(src.feed or src.url)  # the index was read before, but not finished: no conditional GET
        state.etag, state.last_modified, state.checksum = r.etag, r.last_modified, r.checksum()
    else:
        r, changed = _conditional(src, state, fetch)
        if not changed:
            return None
    since = state.cursor.get("since") or (utcnow() - timedelta(days=CSAF_FIRST_DAYS)).strftime("%Y-%m-%dT%H:%M:%S")
    rows = []
    for line in r.text().splitlines():
        parts = [p.strip().strip('"') for p in line.split(",")]
        if len(parts) != 2 or not CSAF_PATH.fullmatch(parts[0]) or ".." in parts[0]:
            continue
        path, ts = parts
        if ts[:19] >= since[:19] and state.cursor.get(f"doc:{path}") != ts:
            rows.append((ts, path))
    rows.sort()
    todo, rest = rows[:CSAF_DOCS_PER_RUN], rows[CSAF_DOCS_PER_RUN:]
    base = (src.feed or src.url).rsplit("/", 1)[0] + "/"
    items = []
    for ts, path in todo:
        state.cursor[f"doc:{path}"] = ts  # also on failure: the fetcher already retried, one document must not block the feed
        try:
            doc = json.loads(fetch.get(urljoin(base, path), max_bytes=CSAF_DOC_BYTES).body)
        except (FetchError, ValueError):
            continue
        it = _csaf_item(src, doc)
        if it:
            items.append(it)
    if rest:
        state.cursor["backlog"] = "1"
    state.cursor["since"] = (rest[0][0] if rest else max([ts for ts, _ in todo] + [since]))[:19]
    for k in [k for k, v in state.cursor.items() if k.startswith("doc:") and v[:19] < state.cursor["since"]]:
        del state.cursor[k]
    return items


def _csaf_item(src: SourceConfig, doc: dict) -> Optional[SourceItem]:
    d = doc.get("document") or {}
    tr = d.get("tracking") or {}
    doc_id = str(tr.get("id") or "")
    if not doc_id:
        return None
    public_id = re.sub(r"^WID-SEC-W-", "WID-SEC-", doc_id)  # the portal name of a WID advisory
    refs = [str(r.get("url")) for r in d.get("references") or [] if r.get("category") == "self" and str(r.get("url", "")).startswith("https://")]
    url = next((u for u in refs if not u.endswith(".json")), refs[0] if refs else src.url)
    notes = {n.get("category"): plain(n.get("text"), 1500) for n in d.get("notes") or [] if n.get("category") != "legal_disclaimer"}
    history = tr.get("revision_history") or []
    latest = plain(history[-1].get("summary"), 300) if history else ""
    # Not the "general" note: it lists operating systems ("Linux, Windows") and would match unrelated products.
    summary = "\n".join(x for x in (notes.get("summary"), notes.get("description"),
                                    f"Revision: {latest}" if latest and len(history) > 1 else "") if x)
    vulns = doc.get("vulnerabilities") or []
    cves = sorted({str(v.get("cve", "")).upper() for v in vulns if CVE_RE.fullmatch(str(v.get("cve", "")))})
    scores = [float(s["cvss_v3"]["baseScore"]) for v in vulns for s in v.get("scores") or []
              if isinstance((s.get("cvss_v3") or {}).get("baseScore"), (int, float))]
    fixed = any((v.get("product_status") or {}).get("fixed") for v in vulns) or any(
        rem.get("category") == "vendor_fix" for v in vulns for rem in v.get("remediations") or [])
    title = plain(d.get("title"), 300) or public_id
    subject = title.split(":", 1)[0].strip() if ":" in title else ""  # "PHP: Mehrere Schwachstellen …" → PHP
    sev = severity_word((d.get("aggregate_severity") or {}).get("text"))
    return SourceItem(
        source_id=src.id, key=doc_id, kind="advisory", url=url, title=title, summary=summary,
        published=parse_date(tr.get("initial_release_date")), updated=parse_date(tr.get("current_release_date")),
        # Multi-vendor coordinator: the vendor comes from the matched catalog product. The product tree also
        # lists every distribution shipping the product (Debian, Fedora …): only the title names the subject.
        product_hints=[subject] if subject else [],
        identifiers=Identifiers(cve=cves, advisory=[public_id]),
        severity=sev or severity_from_score(max(scores) if scores else None),
        cvss=Cvss(score=max(scores), version="3.x", source=src.name) if scores else None,
        fix_available=True if fixed else None,
        checksum=checksum(title, summary, cves, sev, max(scores) if scores else None, fixed, tr.get("version")),
    )


# ---------------------------------------------------------------- Windows release health (known issues)

WRH_PAGE = re.compile(r'href="(/en-us/windows/release-health/status-[a-z0-9-]+)"', re.I)
WRH_BLOCK = re.compile(r'<div id="(\d+)msgdesc"></div>')
WRH_OPENED = re.compile(r"Opened:\s*(\d{4}-\d{2}-\d{2}),\s*(\d{1,2}:\d{2})\s*PT")
PT = timezone(timedelta(hours=-8))  # Pacific time; an hour off in summer is irrelevant for a date


@adapter("ms_release_health")
def ms_release_health(src: SourceConfig, state: SourceState, fetch: Fetcher):
    """Hub page → one status page per Windows version → known issues (the same issue is listed per version)."""
    hub = fetch.get(src.feed or src.url)
    pages = sorted(set(WRH_PAGE.findall(hub.text())))[:15]
    if not pages:
        raise FetchError("release health hub lists no status pages (layout changed?)")
    issues: dict[str, SourceItem] = {}
    for path in pages:
        page_url = urljoin(hub.url, path)
        for it in _wrh_issues(src, page_url, fetch.get(page_url).text()):
            issues.setdefault(it.key, it)
    return list(issues.values())


def _wrh_issues(src: SourceConfig, page_url: str, page: str) -> list[SourceItem]:
    out = []
    marks = list(WRH_BLOCK.finditer(page))
    for n, m in enumerate(marks):
        end = marks[n + 1].start() if n + 1 < len(marks) else len(page)
        chunk = page[m.end():end]
        stop = chunk.find('href="#known-issues"')
        chunk = chunk[:stop] if stop >= 0 else chunk
        h4 = re.search(r"<h4[^>]*>(.*?)</h4>", chunk, re.S)
        table = re.search(r"<table.*?</table>", chunk, re.S)
        if not h4 or not table:
            continue
        cells = re.findall(r"<td[^>]*>(.*?)</td>", table.group(0), re.S)
        if len(cells) < 3:
            continue
        status = (plain(cells[0]).split("\n") or [""])[0].strip()
        origin = plain(cells[1]).replace("\n", " ")
        history = plain(cells[2])
        opened = WRH_OPENED.search(history)
        published = datetime.fromisoformat(f"{opened.group(1)}T{opened.group(2).zfill(5)}").replace(tzinfo=PT) if opened else None
        description = plain(chunk[table.end():], 3000)
        platforms = [p.strip() for line in description.split("\n") if re.match(r"\W*(Client|Server):", line)
                     for p in line.split(":", 1)[1].split(";") if p.strip() and p.strip().lower() != "none"]
        title = plain(h4.group(1), 300)
        kbs = sorted(set(KB_RE.findall(f"{cells[0]} {cells[1]}")))
        out.append(SourceItem(
            source_id=src.id, key=f"wrh-{m.group(1)}", kind="regression", url=f"{page_url}#{m.group(1)}msgdesc",
            title=title, summary=f"Status: {status}. Originating update: {origin}.\n{description}",
            published=published, vendor_hint="Microsoft", product_hints=platforms[:12],
            identifiers=Identifiers(kb=kbs), fix_available=True if status.lower().startswith("resolved") else None,
            checksum=checksum(title, status, origin, description),
        ))
    return out


# ---------------------------------------------------------------- Docker Engine release notes (security fixes)

DOCKER_H2 = re.compile(r"""<h2[^>]*\bid=["']?([\w.-]+)["']?[^>]*>(.*?)</h2>""", re.S)
DOCKER_SECURITY = re.compile(r"""<h3[^>]*\bid=["']?security["' >].*?</h3>(.*?)(?=<h3|$)""", re.S)


@adapter("docker_notes")
def docker_notes(src: SourceConfig, state: SourceState, fetch: Fetcher):
    """Release notes page → versions with a Security section → fix notices (they only add fix information)."""
    r, changed = _conditional(src, state, fetch)
    if not changed:
        return None
    page = r.text()
    heads = list(DOCKER_H2.finditer(page))
    items = []
    for n, h in enumerate(heads):
        version = plain(h.group(2))
        if not re.fullmatch(r"\d+\.\d+\.\d+", version):
            continue
        block = page[h.end():heads[n + 1].start() if n + 1 < len(heads) else len(page)]
        sec = DOCKER_SECURITY.search(block)
        if not sec:
            continue
        text = plain(sec.group(1), 3000)
        ids = identifiers(text)
        if not ids.cve and not ids.advisory:
            continue
        date = re.search(r"<em[^>]*>\s*(\d{4}-\d{2}-\d{2})\s*</em>", block)
        items.append(SourceItem(
            source_id=src.id, key=f"docker-engine-{version}", kind="notice", url=f"{r.url}#{h.group(1)}",
            title=f"Docker Engine {version}", summary=text, published=parse_date(date.group(1)) if date else None,
            vendor_hint="Docker", product_hints=["Docker Engine"], identifiers=ids, fix_available=True,
            checksum=checksum(version, text),
        ))
        if len(items) >= 15:
            break
    return items


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
