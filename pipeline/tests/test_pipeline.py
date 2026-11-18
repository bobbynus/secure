"""Collector tests: parsing, fetch safety, dedup/event building, run isolation, idempotency."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest

from secure_pipeline import adapters as A
from secure_pipeline.cluster import Catalog, Clusterer
from secure_pipeline.fetch import Fetcher, FetchError
from secure_pipeline.models import Cvss, Identifiers, SourceConfig, SourceItem, SourceState
from secure_pipeline.run import run
from secure_pipeline.store import Store
from secure_pipeline.text import identifiers, plain, similarity

NOW = datetime(2026, 11, 18, 12, 0, tzinfo=timezone.utc)
REPO = Path(__file__).resolve().parents[2]


def fetcher(handler, hosts=("feed.example", "other.example")) -> Fetcher:
    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    return Fetcher(hosts, client=client, sleep=lambda s: None)


def src(id="s1", adapter="rss", kind="vendor", vendors=("Fortinet",)) -> SourceConfig:
    return SourceConfig(id=id, name=id.upper(), url="https://feed.example/", kind=kind, format="rss", vendors=list(vendors),
                        adapter=adapter, feed="https://feed.example/feed", state="ok")


def catalog(*sources: SourceConfig) -> Catalog:
    products = json.loads((REPO / "data" / "products.json").read_text(encoding="utf-8"))
    return Catalog(sources={s.id: s for s in sources}, products=products)


def item(source_id="s1", key="k1", kind="advisory", cve=(), **kw) -> SourceItem:
    base = dict(source_id=source_id, key=key, kind=kind, url=f"https://feed.example/{key}", title=kw.pop("title", f"Item {key}"),
                identifiers=Identifiers(cve=list(cve)), published=NOW, checksum=kw.pop("checksum", key))
    base.update(kw)
    return SourceItem(**base)


# ------------------------------------------------------------------ text

def test_plain_strips_markup_and_scripts():
    assert plain("<p>Hello <b>world</b></p><script>alert(1)</script>") == "Hello world"
    assert plain("&lt;p&gt;Encoded &amp;amp; text&lt;/p&gt;") == "Encoded & text"


def test_identifiers():
    ids = identifiers("Fix for cve-2024-3400 and CVE-2024-21762 in FG-IR-24-015, see KB5034441 and USN-6859-1")
    assert ids.cve == ["CVE-2024-21762", "CVE-2024-3400"]
    assert ids.kb == ["KB5034441"]
    assert ids.advisory == ["FG-IR-24-015", "USN-6859-1"]


def test_similarity():
    assert similarity("FortiOS SSL VPN heap overflow", "Heap overflow in FortiOS SSL-VPN") > 0.3
    assert similarity("Exchange RCE", "Debian kernel update") == 0


# ------------------------------------------------------------------ fetch

def test_fetch_blocks_unknown_hosts_and_plain_http():
    f = fetcher(lambda r: httpx.Response(200, text="x"))
    with pytest.raises(FetchError, match="blocked host"):
        f.get("https://evil.example/")
    with pytest.raises(FetchError, match="blocked scheme"):
        f.get("http://feed.example/")


def test_fetch_redirect_to_unknown_host_is_blocked():
    f = fetcher(lambda r: httpx.Response(302, headers={"Location": "https://169.254.169.254/latest"}))
    with pytest.raises(FetchError, match="blocked host"):
        f.get("https://feed.example/a")


def test_fetch_size_limit():
    f = fetcher(lambda r: httpx.Response(200, content=b"x" * 2000))
    with pytest.raises(FetchError, match="too large"):
        f.get("https://feed.example/a", max_bytes=1000)


def test_fetch_retries_then_succeeds_and_conditional_get():
    calls = []

    def handler(r: httpx.Request):
        calls.append(dict(r.headers))
        if len(calls) < 3:
            return httpx.Response(503)
        if r.headers.get("If-None-Match") == '"v1"':
            return httpx.Response(304)
        return httpx.Response(200, text="ok", headers={"ETag": '"v1"'})

    f = fetcher(handler)
    r = f.get("https://feed.example/a")
    assert r.status == 200 and r.etag == '"v1"' and len(calls) == 3
    assert f.get("https://feed.example/a", etag='"v1"').not_modified


# ------------------------------------------------------------------ adapters

KEV = {"catalogVersion": "2026.11.17", "vulnerabilities": [
    {"cveID": "CVE-2026-0001", "vendorProject": "Palo Alto Networks", "product": "PAN-OS", "vulnerabilityName": "PAN-OS RCE",
     "dateAdded": "2026-11-17", "shortDescription": "<b>RCE</b>", "requiredAction": "Patch.", "dueDate": "2026-12-08",
     "knownRansomwareCampaignUse": "Known"},
    {"cveID": "not-a-cve"}]}


def test_kev_adapter_and_not_modified():
    body = json.dumps(KEV).encode()
    f = fetcher(lambda r: httpx.Response(200, content=body, headers={"ETag": "e1"}))
    st = SourceState(id="kev")
    items = A.REGISTRY["cisa_kev"](src("kev", "cisa_kev", "kev"), st, f)
    assert [i.key for i in items] == ["CVE-2026-0001"]
    it = items[0]
    assert it.exploited and it.ransomware and it.kev_added == "2026-11-17" and it.summary.startswith("RCE")
    assert st.etag == "e1"
    # same body again → not modified
    assert A.REGISTRY["cisa_kev"](src("kev", "cisa_kev", "kev"), st, f) is None


RSS = """<?xml version="1.0"?><rss version="2.0"><channel><title>t</title>
<item><title>CVE-2026-0325 PAN-OS: GlobalProtect Bypass (Severity: CRITICAL)</title><link>https://feed.example/CVE-2026-0325</link>
<guid>https://feed.example/CVE-2026-0325</guid><pubDate>Tue, 17 Nov 2026 17:00:00 GMT</pubDate>
<description>Palo Alto Networks is aware of exploitation of this issue.</description></item>
<item><title>Heap overflow</title><link>https://feed.example/FG-IR-26-188</link>
<description><![CDATA[<p><strong>CVSSv3 Score:</strong> 9.8</p><p>FortiOS sslvpnd heap overflow.</p>]]></description></item>
</channel></rss>"""


def test_rss_adapter_severity_exploitation_ids():
    f = fetcher(lambda r: httpx.Response(200, text=RSS))
    items = A.REGISTRY["rss"](src(), SourceState(id="s1"), f)
    a, b = items
    assert a.severity == "critical" and a.exploited is True and a.identifiers.cve == ["CVE-2026-0325"]
    assert b.cvss.score == 9.8 and b.severity == "critical" and b.identifiers.advisory == ["FG-IR-26-188"]


def test_msrc_cvrf_items():
    doc = {"ProductTree": {"FullProductName": [{"ProductID": "1", "Value": "Windows Server 2022"}]}, "Vulnerability": [
        {"CVE": "CVE-2026-1", "Title": {"Value": "Win32k EoP"}, "Notes": [{"Type": 7, "Value": "Windows Win32K"}],
         "Threats": [{"Type": 1, "Description": {"Value": "Publicly Disclosed:No;Exploited:Yes"}}, {"Type": 3, "Description": {"Value": "Important"}}],
         "Remediations": [{"Type": 2, "Description": {"Value": "5044284"}}], "CVSSScoreSets": [{"BaseScore": 7.8}],
         "ProductStatuses": [{"ProductID": ["1"]}], "ReleaseDate": "2026-11-11T08:00:00Z", "ReleaseDateSpecified": True},
        {"CVE": "CVE-2026-2", "Title": {"Value": "libx"}, "Notes": [{"Type": 7, "Value": "Mariner"}]}]}
    items = A._cvrf_items(src("msrc", "msrc"), doc, "2026-Nov")
    assert len(items) == 1
    it = items[0]
    assert it.exploited and it.severity == "high" and it.identifiers.kb == ["KB5044284"] and it.product_hints == ["Windows Server 2022"]


# ------------------------------------------------------------------ clustering

def test_product_matching_uses_word_boundaries():
    cat = catalog()
    assert cat.match_products("Numeric truncation error in FortiOS") == ["fortios"]
    assert "runc" in cat.match_products("runc container breakout")


def test_dedup_across_sources_and_exploitation_revision(tmp_path):
    vendor, kev = src("vendor"), src("kev", "cisa_kev", "kev")
    store = Store(tmp_path)
    cl = Clusterer(store, catalog(vendor, kev), NOW)
    a = cl.process(item("vendor", "adv1", cve=["CVE-2026-9"], title="FortiOS critical", severity="critical",
                        cvss=Cvss(score=9.8, version="3.1", source="x"), fix_available=True))
    assert a.action == "created"
    b = cl.process(item("kev", "CVE-2026-9", kind="kev", cve=["CVE-2026-9"], exploited=True, kev_added="2026-11-18"))
    assert b.action == "updated" and b.event_id == a.event_id and "exploitation" in b.revisions
    e = store.events[a.event_id]
    assert e.kev and e.exploited and e.priority == "critical" and len(e.sources) == 2 and e.products == ["fortios"]
    # Same item again changes nothing.
    assert cl.process(item("kev", "CVE-2026-9", kind="kev", cve=["CVE-2026-9"], exploited=True)).action == "unchanged"


def test_kev_for_old_event_starts_new_related_event(tmp_path):
    kev, vendor = src("kev", "cisa_kev", "kev"), src("vendor")
    store = Store(tmp_path)
    old = Clusterer(store, catalog(vendor, kev), NOW - timedelta(days=400)).process(
        item("vendor", "adv", cve=["CVE-2025-1"], severity="critical", title="FortiOS bug"))
    new = Clusterer(store, catalog(vendor, kev), NOW).process(
        item("kev", "CVE-2025-1", kind="kev", cve=["CVE-2025-1"], exploited=True))
    assert new.action == "created" and new.event_id != old.event_id
    assert store.events[new.event_id].related == [old.event_id]


def test_notices_only_add_fix_information(tmp_path):
    usn, kev = src("ubuntu-usn"), src("kev", "cisa_kev", "kev")
    store = Store(tmp_path)
    cl = Clusterer(store, catalog(usn, kev), NOW)
    assert cl.process(item("ubuntu-usn", "USN-1", kind="notice", cve=["CVE-2026-5"], fix_available=True)).action == "ignored"
    created = cl.process(item("kev", "CVE-2026-6", kind="kev", cve=["CVE-2026-6"], exploited=True))
    out = cl.process(item("ubuntu-usn", "USN-2", kind="notice", cve=["CVE-2026-6"], fix_available=True))
    assert out.event_id == created.event_id and out.revisions == ("fix",)


def test_non_infrastructure_critical_is_not_newsworthy(tmp_path):
    cl = Clusterer(Store(tmp_path), catalog(src()), NOW)
    assert cl.process(item(title="Critical bug in some photo app", severity="critical",
                           cvss=Cvss(score=9.8, version="3.1", source="x"))).action == "ignored"
    assert cl.process(item(key="k2", title="Medium FortiOS issue", severity="medium")).action == "ignored"


def test_items_without_ids_merge_by_title(tmp_path):
    s = src(vendors=("Microsoft",))
    store = Store(tmp_path)
    cl = Clusterer(store, catalog(s), NOW)
    a = cl.process(item(key="a", kind="regression", title="Windows Server 2025 update fails with 0x800f0922", vendor_hint="Microsoft"))
    b = cl.process(item(key="b", kind="regression", title="Update fails with 0x800f0922 on Windows Server 2025", vendor_hint="Microsoft"))
    assert a.action == "created" and b.event_id == a.event_id


# ------------------------------------------------------------------ run

def _catalog_dir(tmp_path: Path, sources: list[dict]) -> Path:
    d = tmp_path / "data"
    d.mkdir()
    (d / "sources.json").write_text(json.dumps(sources), encoding="utf-8")
    (d / "products.json").write_text((REPO / "data" / "products.json").read_text(encoding="utf-8"), encoding="utf-8")
    return d


def test_run_isolates_failing_source_bootstraps_and_is_idempotent(tmp_path):
    kev_doc = {"vulnerabilities": [
        {"cveID": "CVE-2026-1001", "vendorProject": "X", "product": "Y", "vulnerabilityName": "new", "dateAdded": "2026-11-17"},
        {"cveID": "CVE-2020-1001", "vendorProject": "X", "product": "Y", "vulnerabilityName": "old", "dateAdded": "2021-01-01"}]}

    def handler(r: httpx.Request):
        if r.url.host == "feed.example":
            return httpx.Response(200, json=kev_doc)
        return httpx.Response(404)

    data = _catalog_dir(tmp_path, [
        {"id": "kev", "name": "KEV", "url": "https://feed.example/", "kind": "kev", "format": "json", "adapter": "cisa_kev",
         "feed": "https://feed.example/kev.json", "state": "ok"},
        {"id": "broken", "name": "B", "url": "https://other.example/", "kind": "vendor", "format": "rss", "adapter": "rss",
         "feed": "https://other.example/feed", "state": "ok"},
    ])
    state = tmp_path / "state"
    status = run(data, state, now=NOW, fetcher=fetcher(handler), log=lambda s: None)
    by_id = {s["id"]: s for s in status["sources"]}
    assert by_id["kev"]["state"] == "ok" and by_id["broken"]["state"] == "error" and "HTTP 404" in by_id["broken"]["lastError"]
    assert status["totals"]["events_created"] == 1  # the 2021 entry is baseline, not news
    again = run(data, state, now=NOW + timedelta(hours=1), fetcher=fetcher(handler), log=lambda s: None)
    assert again["totals"]["items_new"] == 0 and again["events"]["total"] == 1
