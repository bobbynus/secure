"""Adapters and clustering rules for CERT-Bund (CSAF), ZDI, BleepingComputer, Ivanti, Windows release health, Docker."""

from __future__ import annotations

import json
from datetime import timedelta

import httpx

from secure_pipeline import adapters as A
from secure_pipeline.cluster import Clusterer
from secure_pipeline.models import Cvss, Identifiers, SourceState, utcnow
from secure_pipeline.store import Store
from test_pipeline import NOW, catalog, fetcher, item, src


# ------------------------------------------------------------------ CSAF (CERT-Bund WID)

def _csaf_doc(n: int, title="Fortinet FortiOS: Schwachstelle ermöglicht Codeausführung", cves=("CVE-2026-9001",)) -> dict:
    return {
        "document": {
            "title": title, "aggregate_severity": {"text": "kritisch"}, "lang": "de-DE",
            "notes": [{"category": "legal_disclaimer", "text": "…"}, {"category": "summary", "text": "Ein Angreifer kann …"},
                      {"category": "general", "text": "- Linux\n- Windows"}],
            "references": [{"category": "self", "url": f"https://feed.example/2026/wid-sec-w-2026-{n:04d}.json"},
                           {"category": "self", "url": f"https://feed.example/portal?name=WID-SEC-2026-{n:04d}"}],
            "tracking": {"id": f"WID-SEC-W-2026-{n:04d}", "version": "1", "initial_release_date": "2026-11-17T23:00:00.000+00:00",
                         "current_release_date": "2026-11-17T23:00:00.000+00:00", "revision_history": [{"summary": "Initiale Fassung"}]},
        },
        "product_tree": {"branches": [{"category": "vendor", "name": "Debian", "branches": [{"category": "product_name", "name": "Debian Linux"}]}]},
        "vulnerabilities": [{"cve": c, "product_status": {"fixed": ["T1"]}, "scores": [{"cvss_v3": {"baseScore": 9.6}}]} for c in cves],
    }


def test_csaf_reads_changed_documents_with_backlog(monkeypatch):
    ts = (utcnow() - timedelta(hours=3)).strftime("%Y-%m-%dT%H:%M:%S+0000")
    old = (utcnow() - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%S+0000")
    changes = "\n".join([f'"2026/wid-sec-w-2026-{n:04d}.json","{ts}"' for n in (1, 2, 3)]
                        + ['"../etc/passwd.json","%s"' % ts, f'"2026/wid-sec-w-2026-0099.json","{old}"'])
    calls = []

    def handler(r: httpx.Request):
        calls.append(r.url.path)
        if r.url.path.endswith("changes.csv"):
            return httpx.Response(200, text=changes, headers={"ETag": "c1"})
        n = int(r.url.path.rsplit("-", 1)[1].split(".")[0])
        return httpx.Response(200, json=_csaf_doc(n))

    monkeypatch.setattr(A, "CSAF_DOCS_PER_RUN", 2)
    s = src("cert-bund-wid", "csaf", "cert", vendors=())
    s.feed = "https://feed.example/csaf/changes.csv"
    st = SourceState(id=s.id)
    first = A.REGISTRY["csaf"](s, st, fetcher(handler))
    assert [i.key for i in first] == ["WID-SEC-W-2026-0001", "WID-SEC-W-2026-0002"] and st.cursor.get("backlog") == "1"
    it = first[0]
    assert it.identifiers.cve == ["CVE-2026-9001"] and it.identifiers.advisory == ["WID-SEC-2026-0001"]
    assert it.url == "https://feed.example/portal?name=WID-SEC-2026-0001" and it.severity == "critical" and it.cvss.score == 9.6
    assert it.product_hints == ["Fortinet FortiOS"] and "Linux" not in it.summary and it.fix_available is True
    # Backlog: the next run reads the index again (no conditional GET) and takes the rest.
    second = A.REGISTRY["csaf"](s, st, fetcher(handler))
    assert [i.key for i in second] == ["WID-SEC-W-2026-0003"] and "backlog" not in st.cursor
    assert not any("passwd" in c or "0099" in c for c in calls)
    # Nothing new: 304 → None.
    assert A.REGISTRY["csaf"](s, st, fetcher(lambda r: httpx.Response(304))) is None


# ------------------------------------------------------------------ RSS: ZDI, Ivanti, BleepingComputer

ZDI = """<?xml version="1.0"?><rss version="2.0"><channel><title>ZDI</title>
<item><title>ZDI-26-1037: Fortinet FortiOS Authentication Bypass Vulnerability</title><guid>ZDI-CAN-1</guid>
<link>http://feed.example/advisories/ZDI-26-1037/</link><pubDate>Wed, 18 Nov 2026 00:00:00 -0600</pubDate>
<description>Authentication is not required to exploit this vulnerability. The ZDI has assigned a CVSS rating of 9.8. The following CVEs are assigned: CVE-2026-1234.</description></item>
</channel></rss>"""


def test_zdi_feed_cvss_ids_and_https_links():
    s = src("zdi-advisories", kind="research", vendors=())
    (it,) = A.REGISTRY["rss"](s, SourceState(id=s.id), fetcher(lambda r: httpx.Response(200, text=ZDI)))
    assert it.url == "https://feed.example/advisories/ZDI-26-1037/"
    assert it.cvss.score == 9.8 and it.severity == "critical" and it.exploited is None
    assert it.identifiers.cve == ["CVE-2026-1234"] and it.identifiers.advisory == ["ZDI-26-1037"]


IVANTI = """<?xml version="1.0"?><rss version="2.0"><channel><title>Ivanti</title>
<item><guid>g1</guid><link>https://feed.example/blog/november</link><title>November Security Update</title>
<description>&lt;p&gt;We have no evidence of these vulnerabilities being exploited in the wild.&lt;/p&gt;
&lt;a href="https://forums.example/s/article/Security-Advisory-Ivanti-Sentry-CVE-2026-105425-CVE-2026-105669"&gt;Ivanti Sentry&lt;/a&gt;</description></item>
</channel></rss>"""


def test_ivanti_ids_come_from_advisory_links_and_negation_holds():
    s = src("ivanti-advisories", vendors=("Ivanti",))
    (it,) = A.REGISTRY["rss"](s, SourceState(id=s.id), fetcher(lambda r: httpx.Response(200, text=IVANTI)))
    assert it.identifiers.cve == ["CVE-2026-105425", "CVE-2026-105669"] and it.exploited is None


BC = """<?xml version="1.0"?><rss version="2.0"><channel><title>BC</title>
<item><title>Hackers exploit FortiOS flaw in zero-day attacks</title><link>https://feed.example/news/a</link><guid>a</guid>
<description>Fortinet warns of a flaw. [...]</description></item>
<item><title>Arrests in ransomware case</title><link>https://feed.example/news/b</link><guid>b</guid><description>Police …</description></item>
</channel></rss>"""
ARTICLE = """<html><nav>CVE-2020-0001 trending</nav><div class="articleBody"><p>The flaw, tracked as CVE-2026-5555, …</p>
<p>Last year attackers abused CVE-2025-1111 in a similar way.</p><p>Patch CVE-2026-5555 now.</p></div>
<h2>Related Articles</h2><p>CVE-2026-7777 exploited</p></html>"""


def test_media_article_body_gives_main_cve_politely():
    pauses = []

    def handler(r: httpx.Request):
        if r.url.path == "/feed":
            return httpx.Response(200, text=BC)
        return httpx.Response(200, text=ARTICLE if r.url.path == "/news/a" else "<p>no body marker CVE-2026-8888</p>")

    f = fetcher(handler)
    f.sleep = pauses.append
    s = src("bleepingcomputer", kind="media", vendors=())
    st = SourceState(id=s.id)
    a, b = A.REGISTRY["rss"](s, st, f)
    assert a.kind == "article" and a.exploited is True and a.identifiers.cve == ["CVE-2026-5555"]
    assert b.identifiers.cve == []  # page without the article marker: nothing from navigation or sidebars
    assert pauses == [A.ARTICLE_DELAY]
    # Seen articles are not fetched again.
    st.seen, st.checksum = {"a": a.checksum, "b": b.checksum}, None
    pages = []
    f2 = fetcher(lambda r: pages.append(r.url.path) or httpx.Response(200, text=BC))
    A.REGISTRY["rss"](s, st, f2)
    assert pages == ["/feed"]


# ------------------------------------------------------------------ Windows release health

HUB = '<a href="/en-us/windows/release-health/status-windows-11-25H2">11</a><a href="/en-us/windows/release-health/status-windows-server-2025">S</a>'
STATUS = """<h2 id="issue-details">Issue details</h2><h3>November 2026</h3><div id="3721msgdesc"></div>
<h4 class="x"><p>SQL Server linked server connections might remain open</p></h4><p></p><table border="0"><tbody>
<tr><th>Status</th><th>Originating update</th><th>History</th></tr>
<tr><td>Resolved<br><a href="https://support.microsoft.com/help/5132061">KB5132061</a></td><td>OS Build 26200.9711<br> <a>KB5127648</a><br>2026-10-13</td>
<td>Last updated: 2026-11-11, 15:37 PT<br>Opened: 2026-11-11, 15:11 PT</td></tr></tbody></table>
<p>After installing KB5127648 connections might remain open.</p><p><strong>Affected platforms:</strong></p>
<ul><li>Client: None</li><li>Server: Windows Server 2025; Windows Server 2022</li></ul><div align="right"><a href="#known-issues">Back</a></div>
<div id="4984msgdesc"></div><h4><p>USB audio might fail</p></h4><table><tr><td>Confirmed</td><td>KB5124008</td><td>Opened: 2026-09-08, 10:00 PT</td></tr></table>"""


def test_release_health_known_issues_deduplicated_across_pages():
    def handler(r: httpx.Request):
        return httpx.Response(200, text=STATUS if "status-" in r.url.path else HUB)

    s = src("ms-release-health", "ms_release_health", vendors=("Microsoft",))
    items = {i.key: i for i in A.REGISTRY["ms_release_health"](s, SourceState(id=s.id), fetcher(handler))}
    assert set(items) == {"wrh-3721", "wrh-4984"}
    it = items["wrh-3721"]
    assert it.kind == "regression" and it.fix_available is True and it.identifiers.kb == ["KB5127648", "KB5132061"]
    assert it.product_hints == ["Windows Server 2025", "Windows Server 2022"]
    assert it.published.isoformat() == "2026-11-11T15:11:00-08:00" and it.url.endswith("#3721msgdesc")
    assert items["wrh-4984"].fix_available is None


# ------------------------------------------------------------------ Docker release notes

DOCKER = """<h2 id=search-heading>Search</h2>
<h2 class="x" id=29100><a href=#29100>29.10.0</a></h2><em class=i>2026-11-16</em><h3 id=networking>Networking</h3><ul><li>Fix MTU</li></ul>
<h2 class="x" id=2993><a href=#2993>29.9.3</a></h2><em class=i>2026-11-03</em><h3 class="x" id=security><a>Security</a></h3>
<ul><li><strong>CVE-2026-116587</strong> Fix CPU usage <a href=https://github.com/advisories/GHSA-mgcc-cww5-fp2q>GHSA-mgcc-cww5-fp2q</a></li></ul>
<h3 id=api>API</h3><ul><li>CVE-2026-0000 is not security of this release</li></ul><h2 id=footer-x>Footer</h2>"""


def test_docker_security_sections_become_fix_notices():
    s = src("docker-engine-notes", "docker_notes", vendors=("Docker",))
    (it,) = A.REGISTRY["docker_notes"](s, SourceState(id=s.id), fetcher(lambda r: httpx.Response(200, text=DOCKER)))
    assert it.key == "docker-engine-29.9.3" and it.kind == "notice" and it.fix_available is True
    assert it.identifiers.cve == ["CVE-2026-116587"] and it.identifiers.advisory == ["GHSA-mgcc-cww5-fp2q"]
    assert it.published.date().isoformat() == "2026-11-03" and it.url.endswith("#2993")


# ------------------------------------------------------------------ clustering rules

def test_same_source_message_returns_to_its_event(tmp_path):
    s = src(vendors=("Microsoft",))
    store = Store(tmp_path)
    cl = Clusterer(store, catalog(s), NOW)
    a = cl.process(item(key="wrh-1", kind="regression", title="Printing fails", vendor_hint="Microsoft"))
    # Retitled by the vendor: title similarity is gone, the source reference still links it.
    b = cl.process(item(key="wrh-1", kind="regression", title="Some apps cannot print after KB5000001",
                        vendor_hint="Microsoft", fix_available=True, checksum="v2"))
    assert b.event_id == a.event_id and "fix" in b.revisions and len(store.events) == 1


def test_update_issues_and_vulnerabilities_do_not_merge_by_kb(tmp_path):
    vendor = src("msrc", vendors=("Microsoft",))
    wrh = src("ms-release-health", vendors=("Microsoft",))
    cl = Clusterer(Store(tmp_path), catalog(vendor, wrh), NOW)
    vuln = cl.process(item("msrc", "CVE-2026-1", title="Win32k EoP", exploited=True,
                           identifiers=Identifiers(cve=["CVE-2026-1"], kb=["KB5044284"])))
    # Two issues caused by the same KB are separate events; a vulnerability fixed by that KB is a third one.
    one = cl.process(item("ms-release-health", "wrh-3", kind="regression", title="Audio stops after update",
                          identifiers=Identifiers(kb=["KB5044284"])))
    two = cl.process(item("ms-release-health", "wrh-4", kind="regression", title="VPN drops on reconnect",
                          identifiers=Identifiers(kb=["KB5044284"])))
    fix = cl.process(item("msrc", "CVE-2026-2", title="Kernel EoP", exploited=True,
                          identifiers=Identifiers(cve=["CVE-2026-2"], kb=["KB5044284"])))
    assert one.action == two.action == fix.action == "created"
    assert vuln.action == "created" and len({one.event_id, two.event_id, fix.event_id, vuln.event_id}) == 4


def test_secondary_sources_add_context_but_not_facts(tmp_path):
    vendor, wid, bc = src("vendor"), src("cert-bund-wid", kind="cert", vendors=()), src("bleepingcomputer", kind="media", vendors=())
    store = Store(tmp_path)
    cl = Clusterer(store, catalog(vendor, wid, bc), NOW)
    created = cl.process(item("vendor", "adv1", cve=["CVE-2026-9"], title="FortiOS heap overflow", severity="critical",
                              cvss=Cvss(score=9.1, version="3.1", source="Fortinet")))
    bundle = [f"CVE-2026-{n}" for n in range(9, 60)]
    out = cl.process(item("cert-bund-wid", "WID-1", cve=bundle, title="Linux Kernel: Mehrere Schwachstellen", severity="critical",
                          cvss=Cvss(score=9.8, version="3.x", source="CERT-Bund"), fix_available=True))
    news = cl.process(item("bleepingcomputer", "art", kind="article", cve=["CVE-2026-9"], title="FortiOS flaw exploited in attacks",
                           exploited=True))
    e = store.events[created.event_id]
    assert out.event_id == news.event_id == created.event_id
    assert e.identifiers.cve == ["CVE-2026-9"] and e.cvss.score == 9.1 and e.cvss.source == "Fortinet"
    assert not e.exploited and e.fix == "unknown" and len(e.sources) == 3
    assert "cert-bund-wid:WID-1" not in e.texts and "bleepingcomputer:art" in e.texts  # a bundle's text is noise


def test_secondary_sources_open_events_only_with_cve_and_catalog_product(tmp_path):
    bc, wid = src("bleepingcomputer", kind="media", vendors=()), src("cert-bund-wid", kind="cert", vendors=())
    store = Store(tmp_path)
    cl = Clusterer(store, catalog(bc, wid), NOW)
    assert cl.process(item("bleepingcomputer", "x", kind="article", title="Hackers exploit FortiOS flaw", exploited=True)).action == "ignored"
    assert cl.process(item("bleepingcomputer", "y", kind="article", cve=["CVE-2026-3"], title="Roller RCE exploited",
                           exploited=True)).action == "ignored"
    out = cl.process(item("bleepingcomputer", "z", kind="article", cve=["CVE-2026-4"], title="FortiOS flaw exploited in attacks",
                          exploited=True))
    e = store.events[out.event_id]
    assert out.action == "created" and e.confirmation == "preliminary" and e.vendor == "Fortinet" and e.reason == "media report exploitation"
    # CERT-Bund confirms it: official, still no new facts from the bundle text.
    cl.process(item("cert-bund-wid", "WID-2", cve=["CVE-2026-4"], title="Fortinet FortiOS: Schwachstelle"))
    assert e.confirmation == "official"


def test_old_messages_open_events_only_for_exploitation(tmp_path):
    vendor = src("vendor")
    cl = Clusterer(Store(tmp_path), catalog(vendor), NOW)
    old = NOW - timedelta(days=200)
    assert cl.process(item("vendor", "a", cve=["CVE-2025-1"], title="FortiOS critical", severity="critical", published=old)).action == "ignored"
    assert cl.process(item("vendor", "b", cve=["CVE-2025-2"], title="FortiOS bug", exploited=True, published=old)).action == "created"
