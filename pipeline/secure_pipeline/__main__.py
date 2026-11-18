"""CLI: python -m secure_pipeline <collect|ai|publish|withdraw|queue|ai-eval|report|health|push-status> …"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx

from .models import utcnow
from .run import allowed_hosts, load_catalog, run
from .store import Store

REPO = Path(__file__).resolve().parents[2]


def _provider():
    from .ai.provider import Gemini

    key = os.environ.get("GEMINI_API_KEY", "").strip()
    if not key:
        return None
    models = [m.strip() for m in os.environ.get("GEMINI_MODELS", "").split(",") if m.strip()] or None
    return Gemini(key, models, min_interval=float(os.environ.get("GEMINI_MIN_INTERVAL", "6.5")))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="secure_pipeline")
    ap.add_argument("--data", type=Path, default=REPO / "data", help="catalog dir (sources.json, products.json)")
    ap.add_argument("--state", type=Path, default=REPO / "pipeline" / ".state", help="state dir")
    sub = ap.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("collect", help="run due collectors")
    c.add_argument("--only", help="comma-separated source ids")
    c.add_argument("--force", action="store_true", help="ignore source intervals")

    a = sub.add_parser("ai", help="write texts and translations for queued events (needs GEMINI_API_KEY)")
    a.add_argument("--limit", type=int, default=int(os.environ.get("AI_LIMIT", "6")), help="events per run")
    a.add_argument("--publish", action="store_true", help="mark finished events as published")
    a.add_argument("--only", help="comma-separated event ids")

    p = sub.add_parser("publish", help="render published events into data/events")
    p.add_argument("--out", type=Path, default=REPO / "data" / "events")

    w = sub.add_parser("withdraw", help="take an event off the site (its file is removed on the next publish)")
    w.add_argument("id")

    sub.add_parser("queue", help="AI queue and publication state")

    ev = sub.add_parser("ai-eval", help="collect a wider window into a scratch state and test the AI on it")
    ev.add_argument("--out", type=Path, required=True)
    ev.add_argument("--days", type=int, default=45)
    ev.add_argument("--max", type=int, default=40)

    r = sub.add_parser("report", help="list internal events")
    r.add_argument("--limit", type=int, default=30)

    h = sub.add_parser("health", help="exit 1 if the last successful collection is too old")
    h.add_argument("--max-age", default="2h")

    ps = sub.add_parser("push-status", help="send status.json to the site API")
    ps.add_argument("--url", default="https://secure.abramov.vip/api/collector")

    a_ = ap.parse_args(argv)
    cmd = a_.cmd

    if cmd == "collect":
        status = run(a_.data, a_.state, only=set(a_.only.split(",")) if a_.only else None, force=a_.force)
        t = status["totals"]
        print(f"done: {status['run']['ok']} ok / {status['run']['error']} error; items {t['items_new']}, "
              f"events +{t['events_created']} ~{t['events_updated']}; total events {status['events']['total']}")
        return 0

    if cmd == "ai":
        from .fetch import Fetcher
        from .stage4 import process

        provider = _provider()
        if provider is None:
            print("skip: GEMINI_API_KEY is not set")
            return 0
        cat = load_catalog(a_.data)
        store = Store(a_.state)
        fetch = Fetcher(allowed_hosts(cat))
        try:
            st = process(store, cat, provider, fetch, utcnow(), limit=a_.limit, publish=a_.publish,
                         only=set(a_.only.split(",")) if a_.only else None)
        finally:
            fetch.close()
            provider.close()
        _append(a_.state / "ai" / "runs.jsonl", {"at": utcnow().isoformat(), "publish": a_.publish,
                                                 **{k: v for k, v in st.items() if k != "results"}})
        print(f"ai: generated {st['generated']}, failed {st['failed']}, quarantined {st['quarantined']}, "
              f"published {st['published']}, queue {st['queued']}, calls {st['calls']}"
              + (", stopped by quota" if st["quota_stop"] else ""))
        return 0

    if cmd == "publish":
        from .publish import write_all

        cat = load_catalog(a_.data)
        st = write_all(list(Store(a_.state).events.values()), cat, a_.out)
        print(f"publish: written {st['written']}, unchanged {st['unchanged']}, removed {st['removed']}, errors {st['errors']}")
        return 1 if st["errors"] else 0

    if cmd == "withdraw":
        store = Store(a_.state)
        e = store.events.get(a_.id)
        if not e:
            print(f"unknown event {a_.id}")
            return 1
        e.publish_state = "withdrawn"
        store.put_event(e)
        store.flush()
        print(f"{e.id} withdrawn")
        return 0

    if cmd == "queue":
        store = Store(a_.state)
        for e in sorted(store.events.values(), key=lambda e: e.id):
            ai = e.ai
            print(f"{e.id} {e.publish_state:11} texts={'yes' if ai.texts else 'no ':3} attempts={ai.attempts} "
                  f"calls={ai.calls:2} {ai.model or '':24} {(ai.last_error or '')[:70]}")
        return 0

    if cmd == "ai-eval":
        return _eval(a_)

    if cmd == "report":
        store = Store(a_.state)
        for e in sorted(store.events.values(), key=lambda e: e.updated_at, reverse=True)[: a_.limit]:
            flags = ("EXPL " if e.exploited else "") + ("KEV " if e.kev else "")
            print(f"{e.id} {e.priority:8} {flags:9} {e.vendor[:18]:18} {', '.join(e.identifiers.cve[:2]):30} "
                  f"src={len(e.sources)} rev={len(e.revisions)}  {e.title_hint[:70]}")
        return 0

    if cmd == "health":
        status = Store(a_.state).read_status()
        if not status or not status.get("lastSuccess"):
            print("no successful collection yet")
            return 1
        last = datetime.fromisoformat(status["lastSuccess"].replace("Z", "+00:00"))
        n, unit = int(a_.max_age[:-1]), a_.max_age[-1]
        limit = timedelta(**{{"m": "minutes", "h": "hours", "d": "days"}[unit]: n})
        age = datetime.now(timezone.utc) - last
        print(f"last success {status['lastSuccess']} ({int(age.total_seconds() // 60)} min ago); errors: {status['run']['error']}")
        return 0 if age <= limit else 1

    if cmd == "push-status":
        token = os.environ.get("DISPATCH_TOKEN")
        status = Store(a_.state).read_status()
        if not token or not status:
            print("skip: no token or no status")
            return 0
        r = httpx.post(a_.url, json=status, headers={"Authorization": f"Bearer {token}", "User-Agent": "secure-collector"}, timeout=20)
        print(f"push-status: HTTP {r.status_code}")
        return 0 if r.status_code == 200 else 1
    return 2


def _append(f: Path, row: dict):
    f.parent.mkdir(parents=True, exist_ok=True)
    with f.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, ensure_ascii=False) + "\n")


def _eval(a_) -> int:
    """Plan §7.2 / stage 4: test on 30-50 real items — accuracy, identifier safety, quality, cost, latency."""
    from .fetch import Fetcher
    from .stage4 import process

    provider = _provider()
    if provider is None:
        print("GEMINI_API_KEY is not set")
        return 1
    out = Path(a_.out)
    state = out / "state"
    run(a_.data, state, force=True, bootstrap=timedelta(days=a_.days), log=lambda s: None)
    cat = load_catalog(a_.data)
    store = Store(state)
    events = sorted(store.events.values(), key=lambda e: e.event_date, reverse=True)[: a_.max]
    fetch = Fetcher(allowed_hosts(cat))
    try:
        st = process(store, cat, provider, fetch, utcnow(), limit=a_.max, publish=False, only={e.id for e in events})
    finally:
        fetch.close()
        provider.close()
    store = Store(state)
    rows = st["results"]
    ok = [r for r in rows if r["ok"]]
    tokens = sum(r.get("usage", {}).get("totalTokenCount", 0) for r in ok)
    lines = [
        f"# AI evaluation {utcnow().isoformat()}",
        "",
        f"- events tried: {len(rows)} (of {len(store.events)} collected over {a_.days} days)",
        f"- passed all checks: {len(ok)}; first try: {sum(1 for r in ok if r['repairs'] == 0)}; after repair: "
        f"{sum(1 for r in ok if r['repairs'] > 0)}; failed: {len(rows) - len(ok)}",
        f"- model calls: {st['calls']}; tokens (ok events): {tokens}; avg seconds/event: "
        f"{(sum(r['seconds'] for r in ok) / len(ok)) if ok else 0:.1f}",
        f"- affected rows kept/dropped: {sum(r['affected'] for r in ok)}/{sum(r['affected_dropped'] for r in ok)}",
        f"- quota stop: {st['quota_stop']}",
        "",
    ]
    for r in rows:
        e = store.events[r["id"]]
        lines.append(f"## {e.id} — {e.title_hint[:100]}")
        if not r["ok"]:
            lines += [f"FAILED: {r['error']}", *[f"- {p}" for p in r.get("problems", [])], ""]
            continue
        lines.append(f"{r['model']} · calls {r['calls']} · repairs {r['repairs']} · {r['seconds']} s · details {r['details']}")
        for row in e.ai.affected:
            lines.append(f"- affected: {row['product']} | {row['versions']} | fixed {row.get('fixed', '—')}")
        for lang in ("en", "ru", "de"):
            t = e.ai.texts[lang]
            lines += ["", f"**{lang}: {t['title']}**", "", t["summary"], "", f"Impact: {t['impact']}", "",
                      f"Fix: {t['fix']}", *([f"", f"Workaround: {t['workaround']}"] if t.get("workaround") else []),
                      "", *[f"- {c}" for c in t["checks"]]]
        lines.append("")
    (out / "report.md").write_text("\n".join(lines), encoding="utf-8")
    (out / "results.json").write_text(json.dumps(rows, ensure_ascii=False, indent=1), encoding="utf-8")
    print("\n".join(lines[:9]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
