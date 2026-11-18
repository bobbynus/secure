"""Advisory detail pages for the AI step: affected / fixed version tables are often missing from feeds.

Only hosts listed in the source's `detail` allowlist are fetched (same Fetcher: https only, redirects checked,
size-limited). Query strings are dropped (tracking parameters). Text is cached in the state for DETAIL_TTL.
Pages are untrusted data: converted to plain text and passed to the model as quoted source text.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit, urlunsplit

from .cluster import Catalog
from .fetch import Fetcher
from .models import Event
from .text import plain

DETAIL_TTL = timedelta(hours=12)
PAGE_BYTES = 4 * 1024 * 1024
KEEP = 9000


def _focus(text: str, e: Event, title: str) -> str:
    """Skip navigation: start shortly before the first mention of the advisory or its title."""
    marks = [*e.identifiers.advisory, *e.identifiers.cve, title[:50]]
    idx = [i for i in (text.find(m) for m in marks if m) if i >= 0]
    start = max(0, min(idx) - 400) if idx else 0
    return text[start:start + KEEP]


def fetch_details(e: Event, catalog: Catalog, fetch: Fetcher, cache_dir: Path, now: datetime,
                  log: Callable[[str], None] = print) -> dict[str, str]:
    out: dict[str, str] = {}
    for ref in e.sources:
        src = catalog.sources.get(ref.source_id)
        parts = urlsplit(ref.url)
        if not src or not src.detail or parts.scheme != "https" or (parts.hostname or "").lower() not in src.detail:
            continue
        url = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
        f = Path(cache_dir) / f"{hashlib.sha256(url.encode()).hexdigest()[:32]}.json"
        if f.exists():
            c = json.loads(f.read_text(encoding="utf-8"))
            if now - datetime.fromisoformat(c["fetched"]) < DETAIL_TTL:
                if c.get("text"):
                    out[f"{ref.source_id}:{ref.item_key}"] = c["text"]
                continue
        try:
            r = fetch.get(url, max_bytes=PAGE_BYTES)
            text = _focus(plain(r.text(), 200_000), e, ref.title)
        except Exception as ex:  # noqa: BLE001 — details are optional; the feed text is still there
            log(f"      detail {url}: {type(ex).__name__}: {str(ex)[:120]}")
            text = ""
        f.parent.mkdir(parents=True, exist_ok=True)
        tmp = f.with_suffix(".tmp")
        tmp.write_text(json.dumps({"url": url, "fetched": now.isoformat(), "text": text}, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, f)
        if text:
            out[f"{ref.source_id}:{ref.item_key}"] = text
    return out
