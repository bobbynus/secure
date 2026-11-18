"""One collection run: due sources → adapters → new/changed items → events → status.

Guarantees (plan §16, §19):
- a failing source never stops the run; its error is recorded and shown on the site;
- re-running is idempotent: items are processed only if (key, checksum) is new;
- a missed schedule loses nothing: adapters read from the last successful state, not a fixed window;
- first contact with a source only takes items from the last BOOTSTRAP days as new (no archive flood).
"""

from __future__ import annotations

import json
import os
import traceback
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import urlsplit

from . import adapters as A
from .cluster import Catalog, Clusterer
from .fetch import FetchError, Fetcher
from .models import Cvss, SourceConfig, utcnow
from .store import Store

BOOTSTRAP = timedelta(days=14)
NVD_PER_RUN = 10
NVD_TTL = timedelta(days=7)
EXTRA_HOSTS = {"services.nvd.nist.gov"}


def load_catalog(data_dir: Path) -> Catalog:
    sources = [SourceConfig.model_validate(s) for s in json.loads((data_dir / "sources.json").read_text(encoding="utf-8"))]
    products = json.loads((data_dir / "products.json").read_text(encoding="utf-8"))
    return Catalog(sources={s.id: s for s in sources}, products=products)


def allowed_hosts(cat: Catalog) -> set[str]:
    hosts = set(EXTRA_HOSTS)
    for s in cat.sources.values():
        if s.adapter and s.feed:
            hosts.add(urlsplit(s.feed).hostname or "")
    return {h for h in hosts if h}


def run(data_dir: Path, state_dir: Path, *, only: Optional[set[str]] = None, force: bool = False,
        now: Optional[datetime] = None, fetcher: Optional[Fetcher] = None,
        log: Callable[[str], None] = print) -> dict:
    now = now or utcnow()
    cat = load_catalog(data_dir)
    store = Store(state_dir)
    fetch = fetcher or Fetcher(allowed_hosts(cat))
    cl = Clusterer(store, cat, now)
    totals = {"items_new": 0, "events_created": 0, "events_updated": 0, "notifiable": 0}
    report = []

    try:
        for src in cat.sources.values():
            if not src.adapter or (only and src.id not in only):
                continue
            st = store.source_state(src.id)
            if not force and st.last_attempt and now - st.last_attempt < timedelta(seconds=src.interval_seconds() - 120):
                continue
            st.last_attempt = now
            try:
                items = A.REGISTRY[src.adapter](src, st, fetch)
                fresh = [i for i in (items or []) if st.seen.get(i.key) != i.checksum]
                created = updated = 0
                relevant = []  # items that created or changed an event: kept in the audit log
                for it in fresh:
                    if not st.bootstrapped and (it.published is None or it.published < now - BOOTSTRAP):
                        st.seen[it.key] = it.checksum  # baseline: existing archive is not news
                        continue
                    out = cl.process(it)
                    st.seen[it.key] = it.checksum
                    if out.action in ("created", "updated"):
                        relevant.append(it)
                    created += out.action == "created"
                    updated += out.action == "updated"
                    totals["notifiable"] += bool(set(out.revisions) & {"created", "exploitation", "fix"})
                store.log_items(relevant, now)
                if items is not None and len(st.seen) > 5000:
                    current = {i.key for i in items}
                    st.seen = {k: v for k, v in st.seen.items() if k in current}
                st.bootstrapped = True
                st.items_total += len(fresh)
                st.last_success, st.last_error, st.consecutive_failures = now, None, 0
                totals["items_new"] += len(fresh)
                totals["events_created"] += created
                totals["events_updated"] += updated
                log(f"ok    {src.id:24} items {len(fresh):4}  new events {created:3}  updated {updated:3}"
                    + ("  (not modified)" if items is None else ""))
            except Exception as e:  # noqa: BLE001 — isolate every source
                st.consecutive_failures += 1
                st.last_error = _short_error(e)
                log(f"ERROR {src.id:24} {st.last_error}")
                if os.environ.get("PIPELINE_DEBUG"):
                    traceback.print_exc()
            finally:
                store.save_source_state(st)
                store.flush()
            report.append(src.id)

        _enrich_nvd(store, fetch, now, log)
        store.flush()
    finally:
        if fetcher is None:
            fetch.close()

    status = build_status(cat, store, now, totals)
    store.write_status(status)
    return status


def _short_error(e: Exception) -> str:
    msg = str(e).replace("\n", " ")
    return f"{type(e).__name__}: {msg}"[:300] if not isinstance(e, FetchError) else msg[:300]


def _enrich_nvd(store: Store, fetch: Fetcher, now: datetime, log):
    """Fill CVSS from NVD for events that lack it (bounded per run; cached)."""
    key = os.environ.get("NVD_API_KEY") or None
    done = 0
    for e in sorted(store.events.values(), key=lambda e: e.updated_at, reverse=True):
        if done >= NVD_PER_RUN:
            break
        if e.cvss or not e.identifiers.cve:
            continue
        cve = e.identifiers.cve[0]
        cached = store.nvd_get(cve)
        if cached and now - datetime.fromisoformat(cached["fetched"]) < NVD_TTL:
            data = cached.get("data")
        else:
            try:
                data = A.nvd_lookup(fetch, cve, key)
                done += 1
            except Exception as ex:  # noqa: BLE001
                log(f"nvd   {cve}: {_short_error(ex)}")
                continue
            store.nvd_put(cve, {"fetched": now.isoformat(), "data": data})
        if data and data.get("cvss") and data["cvss"].get("score") is not None:
            c = data["cvss"]
            e.cvss = Cvss(score=float(c["score"]), version=str(c["version"]), source="NVD", vector=c.get("vector"))
            if not e.summary_hint and data.get("description"):
                e.summary_hint = data["description"][:1500]
            store.put_event(e)


def build_status(cat: Catalog, store: Store, now: datetime, totals: dict) -> dict:
    sources = []
    for s in cat.sources.values():
        if not s.adapter:
            sources.append({"id": s.id, "state": s.state})
            continue
        st = store.source_state(s.id)
        stale = not st.last_success or now - st.last_success > timedelta(seconds=max(s.interval_seconds() * 4, 7200))
        state = "error" if st.last_error or stale else "ok"
        sources.append({
            "id": s.id, "state": state,
            "lastSuccess": st.last_success.isoformat().replace("+00:00", "Z") if st.last_success else None,
            "lastError": st.last_error, "failures": st.consecutive_failures,
        })
    active = [s for s in sources if s["state"] in ("ok", "error")]
    last_success = max((s["lastSuccess"] for s in sources if s.get("lastSuccess")), default=None)
    return {
        "generatedAt": now.isoformat().replace("+00:00", "Z"),
        "lastSuccess": last_success,
        "run": {"ok": sum(s["state"] == "ok" for s in active), "error": sum(s["state"] == "error" for s in active)},
        "totals": totals,
        "events": {"total": len(store.events), "pending": sum(e.publish_state == "pending" for e in store.events.values())},
        "sources": sources,
    }
