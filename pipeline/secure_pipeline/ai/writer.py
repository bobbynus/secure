"""Facts → English article + grounded affected versions + RU/DE translations (one call), all checked.

Every model answer is validated; one repair round with the list of problems is allowed per step. Validated
answers are cached by (prompt version, step, model, exact input), so re-runs and retries cost no quota.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from ..adapters import exploitation_claimed
from ..cluster import Catalog
from ..models import Event
from . import guard
from .prompts import PROMPT_VERSION, SCHEMA, SYSTEM, base_prompt, repair_prompt
from .provider import Completion, Provider

MAX_SOURCE_CHARS = 7000
MAX_TOTAL_CHARS = 16000  # ~4-5K input tokens: keeps per-minute token use small on a shared quota


class ValidationFailed(Exception):
    def __init__(self, step: str, problems: list[str]):
        super().__init__(f"{step}: " + "; ".join(problems[:6]))
        self.step, self.problems = step, problems


@dataclass
class Generated:
    texts: dict[str, dict]
    affected: list[dict]
    workaround: bool
    model: str
    calls: int = 0
    repairs: int = 0
    usage: dict = field(default_factory=dict)
    latency: float = 0.0
    dropped_affected: int = 0


class Cache:
    def __init__(self, root: Path):
        self.root = Path(root)

    def _file(self, model: str, key: str) -> Path:
        digest = hashlib.sha256((model + "\n" + key).encode()).hexdigest()[:40]
        return self.root / f"{digest}.json"

    def get(self, model: str, key: str) -> Optional[dict]:
        f = self._file(model, key)
        return json.loads(f.read_text(encoding="utf-8")) if f.exists() else None

    def put(self, model: str, key: str, data: dict):
        f = self._file(model, key)
        f.parent.mkdir(parents=True, exist_ok=True)
        tmp = f.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
        os.replace(tmp, f)


# ---------------------------------------------------------------- inputs

def facts(e: Event, catalog: Catalog) -> dict:
    names = {p["id"]: p["name"] for p in catalog.products}
    products = [names[p] for p in e.products if p in names] + [n for n in e.product_names if n and n not in names.values()]
    return {
        "event_id": e.id,
        "category": e.category,
        "vendor": e.vendor,
        "products": products,
        "identifiers": e.identifiers.model_dump(),
        "cvss": {"score": e.cvss.score, "version": e.cvss.version, "source": e.cvss.source} if e.cvss else None,
        "severity": e.severity,
        "exploitation": {
            "in_cisa_kev": e.kev,
            "kev_added": e.kev_added,
            "vendor_reports_exploitation": e.exploited and not e.kev,
            "used_by_ransomware": e.ransomware,
            "reported": e.exploited or e.kev,
        },
        "fix_status": e.fix,
        "sources": [{"ref": f"S{i + 1}", "publisher": s.publisher, "title": s.title, "date": s.date}
                    for i, s in enumerate(e.sources)],
    }


def source_texts(e: Event, details: dict[str, str]) -> list[tuple[str, str, str]]:
    """(ref, header, text) per source; detail pages replace the short feed text when available."""
    out, total = [], 0
    for i, s in enumerate(e.sources):
        tag = f"{s.source_id}:{s.item_key}"
        text = details.get(tag) or e.texts.get(tag) or (e.summary_hint if i == 0 else "") or s.title
        text = text[:MAX_SOURCE_CHARS]
        if total + len(text) > MAX_TOTAL_CHARS:
            text = text[: max(0, MAX_TOTAL_CHARS - total)]
        total += len(text)
        if text:
            out.append((f"S{i + 1}", f"{s.publisher} | {s.date or ''}", text))
    return out


def input_hash(e: Event, catalog: Catalog) -> str:
    """Changes when facts or source texts change → texts are regenerated."""
    blob = json.dumps([PROMPT_VERSION, facts(e, catalog), sorted(e.texts.items())], ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()[:24]


def _fact_ids(e: Event) -> set[str]:
    return set(e.identifiers.keys()) | {i.upper() for i in e.identifiers.cve}


def _fact_numbers(e: Event) -> set[str]:
    out: set[str] = set()
    if e.cvss and e.cvss.score is not None:
        out |= {f"{e.cvss.score:.1f}", str(e.cvss.score)}
        if e.cvss.version and e.cvss.version[0].isdigit():
            out.add(e.cvss.version)
    return out


# ---------------------------------------------------------------- generation

def generate(e: Event, catalog: Catalog, details: dict[str, str], provider: Provider, cache: Cache,
             log: Callable[[str], None] = print) -> Generated:
    f = facts(e, catalog)
    srcs = source_texts(e, details)
    corpus = "\n".join(t for _, _, t in srcs) + "\n" + "\n".join(s.title for s in e.sources)
    fact_ids, fact_nums = _fact_ids(e), _fact_numbers(e)
    exploited = e.exploited or e.kev

    def check(d: dict) -> list[str]:
        a = d.get("en")
        if not isinstance(a, dict):
            return ["'en' object is missing"]
        en_ = _clean_article(a, e.category)
        p = guard.check_base(en_, corpus, fact_ids, fact_nums)
        if not exploited and exploitation_claimed(" \n ".join(guard.article_strings(en_))):
            p.append("the text claims exploitation, but FACTS do not report exploitation; remove that claim")
        if not isinstance(d.get("affected"), list):
            p.append("'affected' must be a list")
        for lang in ("ru", "de"):
            if not isinstance(d.get(lang), dict):
                p.append(f"'{lang}' object is missing")
            else:
                p += guard.check_translation(en_, _clean_article(d[lang], e.category), lang)
        return p

    stats = Generated(texts={}, affected=[], workaround=False, model="")
    prompt = base_prompt(json.dumps(f, ensure_ascii=False, indent=1), srcs)
    out, model = _ask(provider, cache, "article", SYSTEM, prompt, SCHEMA, check, stats, log)
    stats.texts = {lang: _clean_article(out[lang], e.category) for lang in ("en", "ru", "de")}

    rows, dropped = [], 0
    for r in out.get("affected") or []:
        if not isinstance(r, dict):
            continue
        vals = [str(r.get("versions") or ""), str(r.get("fixed") or "")]
        if (r.get("product") and r.get("versions") and guard.grounded_evidence(str(r.get("evidence") or ""), corpus)
                and guard.versions_grounded(vals, corpus)):
            prod = str(r["product"]).strip()[:80]
            ids = catalog.match_products(prod)
            rows.append({"product": ids[0] if len(ids) == 1 and _is_whole_product(prod, ids[0], catalog) else prod,
                         "versions": str(r["versions"]).strip()[:120],
                         **({"fixed": str(r["fixed"]).strip()[:120]} if r.get("fixed") else {})})
        else:
            dropped += 1
    stats.affected = rows
    stats.dropped_affected = dropped
    stats.workaround = bool(stats.texts["en"].get("workaround"))
    stats.model = model
    return stats


def _is_whole_product(name: str, pid: str, catalog: Catalog) -> bool:
    """Use the catalog id only when the row names exactly that product (no branch qualifier)."""
    p = next((p for p in catalog.products if p["id"] == pid), None)
    return bool(p) and guard.norm(name) in {guard.norm(p["name"]), *(guard.norm(m) for m in p.get("match", []))}


def _clean_article(a: dict, category: str) -> dict:
    out = {k: (a.get(k) or "").strip() for k in ("title", "summary", "impact", "fix")}
    w = a.get("workaround")
    out["workaround"] = w.strip() if isinstance(w, str) and w.strip() else None
    out["checks"] = [c.strip() for c in (a.get("checks") or []) if isinstance(c, str) and c.strip()]
    reg = a.get("regression")
    if category == "update-issue" and isinstance(reg, dict) and reg.get("update") and reg.get("symptoms"):
        out["regression"] = {
            "update": str(reg["update"]).strip(), "symptoms": [str(s).strip() for s in reg["symptoms"] if str(s).strip()],
            "conditions": str(reg.get("conditions") or "").strip(), "vendorStatus": str(reg.get("vendorStatus") or "").strip(),
            **({"fixedBy": str(reg["fixedBy"]).strip()} if reg.get("fixedBy") else {}),
            **({"rollback": str(reg["rollback"]).strip()} if reg.get("rollback") else {}),
        }
    else:
        out["regression"] = None
    return out


def _ask(provider: Provider, cache: Cache, step: str, system: str, prompt: str, schema: dict,
         check: Callable[[dict], list[str]], stats: Generated, log) -> tuple[dict, str]:
    key = json.dumps([PROMPT_VERSION, step, system, prompt], ensure_ascii=False)
    for m in provider.models:
        hit = cache.get(m, key)
        if hit is not None and not check(hit):
            return hit, m

    def call(p: str) -> Completion:
        c = provider.complete_json(system, p, schema)
        stats.calls += 1
        stats.latency += c.latency
        for k, v in c.usage.items():
            stats.usage[k] = stats.usage.get(k, 0) + (v or 0)
        return c

    c = call(prompt)
    problems = check(c.data)
    if problems:
        log(f"      {step}: {len(problems)} problem(s), repairing: {problems[0][:120]}")
        stats.repairs += 1
        c = call(repair_prompt(prompt, json.dumps(c.data, ensure_ascii=False), problems))
        problems = check(c.data)
        if problems:
            raise ValidationFailed(step, problems)
    cache.put(c.model, key, c.data)
    return c.data, c.model
