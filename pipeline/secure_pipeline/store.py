"""State store: a directory (in CI: a checkout of the `pipeline-state` branch).

state/
  sources/<id>.json         SourceState (cursor, ETag, seen keys, health)
  events/<id>.json          internal Event
  items/<YYYY-MM>/<src>.jsonl  append-only log of new/changed SourceItems (audit, reprocessing)
  nvd/<CVE>.json            NVD enrichment cache
  counters.json             per-year event sequence
  runs.jsonl                run summaries
  status.json               last run status (also pushed to the site API)
Writes go through a temp file + rename so an interrupted run never leaves half-written JSON.
"""

from __future__ import annotations

import json
import os
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Iterable, Optional

from .models import Event, SourceItem, SourceState


def ref_key(source_id: str, item_key: str) -> str:
    """Index key of one source message (never collides with CVE / KB / advisory identifiers)."""
    return f"ref:{source_id}:{item_key}"


def _write(path: Path, text: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


class Store:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.events: dict[str, Event] = {}
        self._dirty: set[str] = set()
        self._index: dict[str, set[str]] = defaultdict(set)
        for f in sorted((self.root / "events").glob("*.json")):
            e = Event.model_validate_json(f.read_text(encoding="utf-8"))
            self.events[e.id] = e
            self._reindex(e)

    # ---- sources
    def source_state(self, sid: str) -> SourceState:
        f = self.root / "sources" / f"{sid}.json"
        if f.exists():
            return SourceState.model_validate_json(f.read_text(encoding="utf-8"))
        return SourceState(id=sid)

    def save_source_state(self, st: SourceState):
        _write(self.root / "sources" / f"{st.id}.json", st.model_dump_json(indent=1))

    # ---- items
    def log_items(self, items: Iterable[SourceItem], when: datetime):
        by_src: dict[str, list[str]] = defaultdict(list)
        for it in items:
            by_src[it.source_id].append(it.model_dump_json())
        for sid, lines in by_src.items():
            f = self.root / "items" / when.strftime("%Y-%m") / f"{sid}.jsonl"
            f.parent.mkdir(parents=True, exist_ok=True)
            with f.open("a", encoding="utf-8") as fh:
                fh.write("\n".join(lines) + "\n")

    # ---- events
    def _reindex(self, e: Event):
        for k in e.identifiers.keys():
            self._index[k].add(e.id)
        # A later revision of the same source message belongs to the same event, whatever its identifiers.
        for s in e.sources:
            self._index[ref_key(s.source_id, s.item_key)].add(e.id)

    def events_for_keys(self, keys: Iterable[str]) -> list[Event]:
        ids = set().union(*(self._index.get(k, set()) for k in keys)) if keys else set()
        return [self.events[i] for i in sorted(ids)]

    def put_event(self, e: Event):
        self.events[e.id] = e
        self._reindex(e)
        self._dirty.add(e.id)

    def next_event_id(self, year: int) -> str:
        f = self.root / "counters.json"
        counters = json.loads(f.read_text(encoding="utf-8")) if f.exists() else {}
        yy = f"{year % 100:02d}"
        n = int(counters.get(yy, 0)) + 1
        counters[yy] = n
        _write(f, json.dumps(counters, indent=1))
        return f"sr-{yy}-{n:04d}"

    def flush(self):
        for eid in sorted(self._dirty):
            _write(self.root / "events" / f"{eid}.json", self.events[eid].model_dump_json(indent=1))
        self._dirty.clear()

    # ---- NVD cache
    def nvd_get(self, cve: str) -> Optional[dict]:
        f = self.root / "nvd" / f"{cve}.json"
        return json.loads(f.read_text(encoding="utf-8")) if f.exists() else None

    def nvd_put(self, cve: str, data: dict):
        _write(self.root / "nvd" / f"{cve}.json", json.dumps(data, ensure_ascii=False, indent=1))

    # ---- runs
    def write_status(self, status: dict):
        _write(self.root / "status.json", json.dumps(status, ensure_ascii=False, indent=1))
        with (self.root / "runs.jsonl").open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({k: status[k] for k in ("generatedAt", "run", "totals")}, ensure_ascii=False) + "\n")

    def read_status(self) -> Optional[dict]:
        f = self.root / "status.json"
        return json.loads(f.read_text(encoding="utf-8")) if f.exists() else None
