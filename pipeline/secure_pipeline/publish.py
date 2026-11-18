"""Render published events into data/events/<id>.json (the site's content model, site/src/content.config.ts).

A pure function of the state: every run re-renders all published events and writes only what changed, so a
failed commit or deploy is repaired by the next run. Files without a `generated` block (hand-written content)
are never touched. Withdrawn events lose their file.

Deterministic parts (never written by the model): identifiers, CVSS, exploitation status and its sentence,
fix status, dates, sources, revision notes.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Literal, Optional

from pydantic import BaseModel, Field

from .cluster import Catalog
from .models import Event

LANGS = ("ru", "de", "en")
SIGNIFICANT = {"exploitation", "fix", "versions", "workaround", "status", "edit"}
CVSS_VERSIONS = {"3.0", "3.1", "3.x", "4.0"}

# ---------------------------------------------------------------- site schema (mirror of content.config.ts)

SLUG_RE = r"^[a-z0-9]+(?:-[a-z0-9]+)*$"
ISO_DT = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$"
ISO_D = r"^\d{4}-\d{2}-\d{2}$"


class _Reg(BaseModel):
    update: str
    symptoms: list[str] = Field(min_length=1)
    conditions: str
    vendorStatus: str
    fixedBy: Optional[str] = None
    rollback: Optional[str] = None


class _Tr(BaseModel):
    status: Literal["ready", "draft", "failed"]
    slug: str = Field(pattern=SLUG_RE)
    slugHistory: list[str] = Field(default_factory=list)
    title: str = Field(min_length=1)
    summary: str = Field(min_length=1)
    impact: str
    exploitation: str
    fix: str
    workaround: Optional[str] = None
    checks: list[str] = Field(min_length=1)
    regression: Optional[_Reg] = None


class _Src(BaseModel):
    id: str
    title: str
    url: str = Field(pattern=r"^https://")
    publisher: str
    kind: Literal["vendor", "kev", "nvd", "cert", "research", "media", "community"]
    date: Optional[str] = Field(default=None, pattern=ISO_D)


class SiteEvent(BaseModel):
    id: str = Field(pattern=r"^sr-\d{2}-\d{4}$")
    category: Literal["vulnerability", "attack", "update-issue"]
    priority: Literal["critical", "high", "medium", "low", "info"]
    confirmation: Literal["vendor", "official", "preliminary"]
    lifecycle: Literal["detected", "confirmed", "fix-available", "resolved"]
    fix: Literal["available", "partial", "none", "n/a", "unknown"]
    workaround: bool
    exploitation: dict
    vendor: str
    products: list[str]
    identifiers: dict
    affected: list[dict]
    cvss: Optional[dict] = None
    dates: dict
    sources: list[_Src] = Field(min_length=1)
    revisions: list[dict]
    generated: dict
    translations: dict[str, _Tr]


# ---------------------------------------------------------------- slugs, dates, fixed sentences

_RU = dict(zip("абвгдеёжзийклмнопрстуфхцчшщъыьэюя",
               ["a", "b", "v", "g", "d", "e", "e", "zh", "z", "i", "y", "k", "l", "m", "n", "o", "p", "r", "s", "t",
                "u", "f", "kh", "ts", "ch", "sh", "shch", "", "y", "", "e", "yu", "ya"]))
_DE = {"ä": "ae", "ö": "oe", "ü": "ue", "ß": "ss"}


def slugify(text: str, max_len: int = 64) -> str:
    s = "".join(_RU.get(ch, _DE.get(ch, ch)) for ch in text.lower())
    s = re.sub(r"[^a-z0-9]+", "-", s).strip("-")
    if len(s) > max_len:
        s = s[:max_len].rsplit("-", 1)[0]
    return s or "event"


def iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


_MONTHS_EN = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October",
              "November", "December"]


def fmt_date(d: str, lang: str) -> str:
    y, m, day = d.split("-")
    if lang == "en":
        return f"{_MONTHS_EN[int(m) - 1]} {int(day)}, {y}"
    return f"{day}.{m}.{y}"


def exploitation_text(e: Event, lang: str) -> str:
    if e.kev:
        d = fmt_date(e.kev_added, lang) if e.kev_added else None
        s = {
            "ru": f"CISA включило уязвимость в каталог эксплуатируемых уязвимостей (KEV){f' {d}' if d else ''}: зафиксирована эксплуатация в реальных атаках.",
            "de": f"CISA hat die Schwachstelle{f' am {d}' if d else ''} in den Katalog ausgenutzter Schwachstellen (KEV) aufgenommen: Ausnutzung in realen Angriffen ist belegt.",
            "en": f"CISA added the vulnerability to its Known Exploited Vulnerabilities (KEV) catalog{f' on {d}' if d else ''}: exploitation in real attacks is confirmed.",
        }[lang]
        if e.ransomware:
            s += {"ru": " По данным CISA, она используется в кампаниях программ-вымогателей.",
                  "de": " Laut CISA wird sie in Ransomware-Kampagnen eingesetzt.",
                  "en": " CISA reports its use in ransomware campaigns."}[lang]
        return s
    if e.exploited:
        return {"ru": "Производитель сообщает о случаях эксплуатации.",
                "de": "Der Hersteller berichtet von Ausnutzung.",
                "en": "The vendor reports exploitation."}[lang]
    return {"ru": "В использованных источниках нет сведений об эксплуатации.",
            "de": "Die ausgewerteten Quellen enthalten keine Hinweise auf Ausnutzung.",
            "en": "The sources reviewed contain no reports of exploitation."}[lang]


def revision_note(kind: str, facts: dict) -> dict[str, str]:
    if kind == "created":
        return {"ru": "Первая публикация.", "de": "Erstveröffentlichung.", "en": "First published."}
    if kind == "exploitation":
        if facts.get("kev"):
            d = str(facts["kev"])
            return {"ru": f"Добавлено в каталог CISA KEV ({fmt_date(d, 'ru')}).",
                    "de": f"In den CISA-KEV-Katalog aufgenommen ({fmt_date(d, 'de')}).",
                    "en": f"Added to the CISA KEV catalog ({fmt_date(d, 'en')})."}
        return {"ru": "Появились сведения об эксплуатации.", "de": "Hinweise auf Ausnutzung veröffentlicht.",
                "en": "Exploitation reported."}
    if kind == "fix":
        return {"ru": "Появилось исправление.", "de": "Ein Fix ist verfügbar.", "en": "A fix became available."}
    if kind == "status":
        return {"ru": "Обновлены приоритет или статус подтверждения.",
                "de": "Priorität oder Bestätigungsstatus aktualisiert.",
                "en": "Priority or confirmation status updated."}
    if kind == "versions":
        return {"ru": "Изменился список затронутых версий.", "de": "Liste der betroffenen Versionen geändert.",
                "en": "Affected versions changed."}
    return {"ru": "Материал обновлён.", "de": "Beitrag aktualisiert.", "en": "Article updated."}


# ---------------------------------------------------------------- render

def render(e: Event, catalog: Catalog) -> dict:
    ai = e.ai
    assert ai.published_at and ai.texts and ai.generated_at
    published = ai.published_at

    sources, kev_ids, vendor_ids = [], [], []
    for i, s in enumerate(e.sources):
        sid = f"s{i + 1}"
        sources.append({"id": sid, "title": s.title, "url": s.url, "publisher": s.publisher, "kind": s.kind,
                        **({"date": s.date} if s.date else {})})
        (kev_ids if s.kind == "kev" else vendor_ids if s.kind == "vendor" else []).append(sid)

    fix = e.fix
    if fix == "unknown" and any(r.get("fixed") for r in ai.affected):
        fix = "available"
    lifecycle = "fix-available" if fix == "available" else e.lifecycle
    if lifecycle == "fix-available" and fix != "available":
        lifecycle = "confirmed"

    revisions = [{"date": iso(published), "kind": "created", "note": revision_note("created", {})}]
    for r in e.revisions:
        if r.kind in SIGNIFICANT and r.date > published:
            revisions.append({"date": iso(r.date), "kind": r.kind, "note": revision_note(r.kind, r.facts)})
    updated = max([published] + [r.date for r in e.revisions if r.kind in SIGNIFICANT and r.date > published])

    cvss = None
    if e.cvss and e.cvss.score is not None and e.cvss.version in CVSS_VERSIONS:
        cvss = {"score": round(float(e.cvss.score), 1), "version": e.cvss.version, "source": e.cvss.source}

    translations = {}
    for lang in LANGS:
        t = ai.texts[lang]
        tr = {"status": "ready", "slug": ai.slugs[lang], "title": t["title"], "summary": t["summary"],
              "impact": t["impact"], "exploitation": exploitation_text(e, lang), "fix": t["fix"],
              "checks": t["checks"]}
        if t.get("workaround"):
            tr["workaround"] = t["workaround"]
        if t.get("regression"):
            tr["regression"] = t["regression"]
        translations[lang] = tr

    status = "confirmed" if (e.kev or e.exploited) else "none-known"
    out = {
        "id": e.id,
        "category": e.category,
        "priority": e.priority,
        "confirmation": e.confirmation,
        "lifecycle": lifecycle,
        "fix": fix,
        "workaround": ai.workaround,
        "exploitation": {
            "status": status, "kev": e.kev,
            **({"kevAdded": e.kev_added} if e.kev and e.kev_added else {}),
            "evidence": (kev_ids if e.kev else vendor_ids) if status == "confirmed" else [],
        },
        "vendor": e.vendor,
        "products": [p for p in e.products if any(c["id"] == p for c in catalog.products)],
        "identifiers": e.identifiers.model_dump(),
        "affected": ai.affected,
        **({"cvss": cvss} if cvss else {}),
        "dates": {"event": iso(e.event_date), "published": iso(published), "updated": iso(updated)},
        "sources": sources,
        "revisions": revisions,
        "generated": {"model": ai.model or "", "prompt": ai.prompt or "", "at": iso(ai.generated_at)},
        "translations": translations,
    }
    SiteEvent.model_validate(out)
    return out


def freeze_slugs(e: Event):
    for lang in LANGS:
        if lang not in e.ai.slugs:
            e.ai.slugs[lang] = slugify(e.ai.texts[lang]["title"])


def write_all(events: list[Event], catalog: Catalog, out_dir: Path, log=print) -> dict:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    stats = {"written": 0, "unchanged": 0, "removed": 0, "errors": 0}
    for e in events:
        f = out_dir / f"{e.id}.json"
        if e.publish_state == "withdrawn":
            if f.exists() and "generated" in json.loads(f.read_text(encoding="utf-8")):
                f.unlink()
                stats["removed"] += 1
            continue
        if e.publish_state != "published":
            continue
        if f.exists() and "generated" not in json.loads(f.read_text(encoding="utf-8")):
            log(f"skip  {e.id}: hand-written file exists")
            continue
        try:
            text = json.dumps(render(e, catalog), ensure_ascii=False, indent=2) + "\n"
        except Exception as ex:  # noqa: BLE001 — one broken event must not block the others
            stats["errors"] += 1
            log(f"ERROR render {e.id}: {type(ex).__name__}: {str(ex)[:200]}")
            continue
        if f.exists() and f.read_text(encoding="utf-8") == text:
            stats["unchanged"] += 1
            continue
        tmp = f.with_suffix(".tmp")
        tmp.write_text(text, encoding="utf-8", newline="\n")
        tmp.replace(f)
        stats["written"] += 1
    return stats
