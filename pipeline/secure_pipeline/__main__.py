"""CLI: python -m secure_pipeline <collect|report|health|push-status> …"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx

from .run import run
from .store import Store

REPO = Path(__file__).resolve().parents[2]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="secure_pipeline")
    ap.add_argument("--data", type=Path, default=REPO / "data", help="catalog dir (sources.json, products.json)")
    ap.add_argument("--state", type=Path, default=REPO / "pipeline" / ".state", help="state dir")
    sub = ap.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("collect", help="run due collectors")
    c.add_argument("--only", help="comma-separated source ids")
    c.add_argument("--force", action="store_true", help="ignore source intervals")

    r = sub.add_parser("report", help="list internal events")
    r.add_argument("--limit", type=int, default=30)

    h = sub.add_parser("health", help="exit 1 if the last successful collection is too old")
    h.add_argument("--max-age", default="2h")

    p = sub.add_parser("push-status", help="send status.json to the site API")
    p.add_argument("--url", default="https://secure.abramov.vip/api/collector")

    a = ap.parse_args(argv)
    if a.cmd == "collect":
        status = run(a.data, a.state, only=set(a.only.split(",")) if a.only else None, force=a.force)
        t = status["totals"]
        print(f"done: {status['run']['ok']} ok / {status['run']['error']} error; items {t['items_new']}, "
              f"events +{t['events_created']} ~{t['events_updated']}; total events {status['events']['total']}")
        return 0
    if a.cmd == "report":
        store = Store(a.state)
        for e in sorted(store.events.values(), key=lambda e: e.updated_at, reverse=True)[: a.limit]:
            flags = ("EXPL " if e.exploited else "") + ("KEV " if e.kev else "")
            print(f"{e.id} {e.priority:8} {flags:9} {e.vendor[:18]:18} {', '.join(e.identifiers.cve[:2]):30} "
                  f"src={len(e.sources)} rev={len(e.revisions)}  {e.title_hint[:70]}")
        return 0
    if a.cmd == "health":
        status = Store(a.state).read_status()
        if not status or not status.get("lastSuccess"):
            print("no successful collection yet")
            return 1
        last = datetime.fromisoformat(status["lastSuccess"].replace("Z", "+00:00"))
        n, unit = int(a.max_age[:-1]), a.max_age[-1]
        limit = timedelta(**{{"m": "minutes", "h": "hours", "d": "days"}[unit]: n})
        age = datetime.now(timezone.utc) - last
        print(f"last success {status['lastSuccess']} ({int(age.total_seconds() // 60)} min ago); errors: {status['run']['error']}")
        return 0 if age <= limit else 1
    if a.cmd == "push-status":
        token = os.environ.get("DISPATCH_TOKEN")
        status = Store(a.state).read_status()
        if not token or not status:
            print("skip: no token or no status")
            return 0
        r = httpx.post(a.url, json=status, headers={"Authorization": f"Bearer {token}", "User-Agent": "secure-collector"}, timeout=20)
        print(f"push-status: HTTP {r.status_code}")
        return 0 if r.status_code == 200 else 1
    return 2


if __name__ == "__main__":
    sys.exit(main())
