"""Stage 4 queue: which events get texts, retries with backoff, quarantine, publication flag.

- texts are (re)generated when the event's input hash changes (new facts or source texts);
- a failed event is retried with exponential backoff; after MAX_ATTEMPTS it is quarantined (never published
  before) or keeps its previous published texts; it is retried again only when its input changes;
- a daily quota stop ends the step: the rest of the queue waits for the next run;
- with publish=False (dry run) texts are generated and stored, but nothing becomes published.
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta
from typing import Callable, Optional

from .ai.prompts import PROMPT_VERSION
from .ai.provider import Overloaded, ProviderError, QuotaExhausted
from .ai.writer import Cache, ValidationFailed, generate, input_hash
from .cluster import ORDER, Catalog
from .details import fetch_details
from .fetch import Fetcher
from .models import Event
from .publish import freeze_slugs
from .store import Store

MAX_ATTEMPTS = 6
BACKOFF = timedelta(minutes=30)
MAX_BACKOFF = timedelta(hours=12)
STALE = timedelta(days=30)


def _calls(provider) -> int:
    return int(getattr(provider, "calls", 0))


def mark_published(e: Event, now: datetime):
    freeze_slugs(e)
    e.publish_state = "published"
    e.ai.published_at = e.ai.published_at or now


def process(store: Store, catalog: Catalog, provider, fetch: Fetcher, now: datetime, *, limit: int = 6,
            publish: bool = False, only: Optional[set[str]] = None, log: Callable[[str], None] = print) -> dict:
    cache = Cache(store.root / "ai" / "cache")
    stats = {"generated": 0, "failed": 0, "quarantined": 0, "published": 0, "queued": 0, "calls": 0,
             "quota_stop": False, "results": []}
    queue: list[tuple[Event, str]] = []
    for e in store.events.values():
        if only and e.id not in only:
            continue
        if e.publish_state in ("withdrawn", "skipped"):
            continue
        h = input_hash(e, catalog)
        if e.ai.input_hash == h and e.ai.texts:
            if publish and e.publish_state == "pending":
                mark_published(e, now)
                store.put_event(e)
                stats["published"] += 1
            continue
        if e.ai.failed_hash == h:
            continue
        if e.ai.next_try and e.ai.next_try > now:
            continue
        if e.publish_state == "pending" and not e.ai.texts and now - e.created_at > STALE:
            e.publish_state = "skipped"  # too old to be news by the time texts could be written
            store.put_event(e)
            continue
        queue.append((e, h))

    # New events first (by editorial priority, newest first), then updates of published ones.
    queue.sort(key=lambda x: (x[0].publish_state == "published", -ORDER.index(x[0].priority),
                              -x[0].created_at.timestamp()))
    stats["queued"] = len(queue)

    for e, h in queue[:limit]:
        before = _calls(provider)
        started = time.monotonic()
        log(f"ai    {e.id} {e.priority:8} {e.title_hint[:70]}")
        try:
            details = fetch_details(e, catalog, fetch, store.root / "details", now, log)
            g = generate(e, catalog, details, provider, cache, log)
        except (QuotaExhausted, Overloaded) as ex:
            stats["quota_stop"] = True
            log(f"      stop: {ex}; the queue waits for the next run")
            break
        except (ValidationFailed, ProviderError) as ex:
            _fail(e, h, ex, now)
            e.ai.calls += _calls(provider) - before
            store.put_event(e)
            stats["failed"] += 1
            stats["quarantined"] += e.publish_state == "quarantined"
            stats["results"].append({"id": e.id, "ok": False, "error": str(ex)[:300],
                                     "problems": getattr(ex, "problems", [])[:10]})
            log(f"      FAILED (attempt {e.ai.attempts}): {str(ex)[:200]}")
            continue
        finally:
            stats["calls"] += _calls(provider) - before

        e.ai.texts, e.ai.affected, e.ai.workaround = g.texts, g.affected, g.workaround
        e.ai.input_hash, e.ai.model, e.ai.prompt, e.ai.generated_at = h, g.model, PROMPT_VERSION, now
        e.ai.attempts, e.ai.last_error, e.ai.next_try, e.ai.failed_hash = 0, None, None, None
        e.ai.calls += _calls(provider) - before
        if e.publish_state == "quarantined":
            e.publish_state = "pending"
        if publish and e.publish_state == "pending":
            mark_published(e, now)
            stats["published"] += 1
        store.put_event(e)
        stats["generated"] += 1
        stats["results"].append({"id": e.id, "ok": True, "calls": g.calls, "repairs": g.repairs, "model": g.model,
                                 "usage": g.usage, "seconds": round(time.monotonic() - started, 1),
                                 "affected": len(g.affected), "affected_dropped": g.dropped_affected,
                                 "details": len(details)})
        log(f"      ok: {g.calls} call(s), {g.repairs} repair(s), affected rows {len(g.affected)}"
            f" (dropped {g.dropped_affected}), {g.model}")
    store.flush()
    return stats


def _fail(e: Event, h: str, ex: Exception, now: datetime):
    e.ai.attempts += 1
    e.ai.last_error = str(ex)[:300]
    e.ai.next_try = now + min(BACKOFF * 2 ** (e.ai.attempts - 1), MAX_BACKOFF)
    if e.ai.attempts >= MAX_ATTEMPTS:
        e.ai.failed_hash, e.ai.attempts, e.ai.next_try = h, 0, None
        if e.publish_state == "pending":
            e.publish_state = "quarantined"
