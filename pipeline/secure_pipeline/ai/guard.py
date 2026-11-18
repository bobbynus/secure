"""Deterministic checks of model output (plan §7, steps 3 and 6).

Protected tokens: CVE / KB / advisory IDs, version-like numbers (7.4.13, 12.1.3-h3, 9.8) and `code spans`.
- base (English) text: every protected token must come from the facts or the source texts;
- translations: the set of protected tokens must equal the English one, in every language;
- no URLs anywhere (sources are listed by the site), plausible language, length limits.
"""

from __future__ import annotations

import re
from typing import Iterable

from ..text import ADVISORY_RES, CVE_RE, KB_RE

VERSION_RE = re.compile(r"(?<![\w.\-])\d+(?:\.\d+)+(?:-[A-Za-z]{1,3}\d+)?(?![\w.]*\d)")
DATE_LIKE_RE = re.compile(r"^\d{1,2}\.\d{1,2}\.(?:19|20)\d{2}$")  # 13.11.2026 (not 7.4.13)
CODE_RE = re.compile(r"`([^`\n]{1,300})`")
URL_RE = re.compile(r"https?://|\bwww\.[a-z0-9-]+\.", re.I)
CYRILLIC_RE = re.compile(r"[А-Яа-яЁё]")
LATIN_RE = re.compile(r"[A-Za-z]")
GERMAN_HINT_RE = re.compile(r"\b(der|die|das|und|ist|nicht|für|mit|wird|werden|auf|eine?n?|sie|von|zu)\b", re.I)

LIMITS = {"title": 140, "summary": 420, "impact": 900, "fix": 900, "workaround": 700, "check": 320}


def ids_in(text: str) -> set[str]:
    out = {m.upper() for m in CVE_RE.findall(text)} | set(KB_RE.findall(text))
    for r in ADVISORY_RES:
        out |= set(r.findall(text))
    return out


def versions_in(text: str) -> set[str]:
    return {v for v in VERSION_RE.findall(text) if not DATE_LIKE_RE.match(v)}


def codes_in(text: str) -> set[str]:
    return {c.strip() for c in CODE_RE.findall(text)}


def norm(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip().lower()


def tokens(text: str) -> set[str]:
    return ids_in(text) | versions_in(text) | {f"`{c}`" for c in codes_in(text)}


def article_strings(a: dict) -> list[str]:
    """All text of an article dict (title, summary, impact, fix, workaround, checks, regression)."""
    out = [a.get(k) or "" for k in ("title", "summary", "impact", "fix", "workaround")]
    out += list(a.get("checks") or [])
    reg = a.get("regression") or {}
    if reg:
        out += [reg.get(k) or "" for k in ("update", "conditions", "vendorStatus", "fixedBy", "rollback")]
        out += list(reg.get("symptoms") or [])
    return [s for s in out if s]


def _shape(a: dict, lang: str) -> list[str]:
    p = []
    for k in ("title", "summary", "impact", "fix"):
        v = a.get(k)
        if not isinstance(v, str) or not v.strip():
            p.append(f"{lang}: field '{k}' is empty")
        elif len(v) > LIMITS[k]:
            p.append(f"{lang}: field '{k}' is longer than {LIMITS[k]} characters")
    w = a.get("workaround")
    if w is not None and (not isinstance(w, str) or len(w) > LIMITS["workaround"]):
        p.append(f"{lang}: field 'workaround' must be null or a string up to {LIMITS['workaround']} characters")
    checks = a.get("checks")
    if not isinstance(checks, list) or not 1 <= len(checks) <= 5 or not all(isinstance(c, str) and c.strip() for c in checks):
        p.append(f"{lang}: 'checks' must contain 1 to 5 non-empty strings")
    elif any(len(c) > LIMITS["check"] for c in checks):
        p.append(f"{lang}: a check is longer than {LIMITS['check']} characters")
    for s in article_strings(a):
        if URL_RE.search(s):
            p.append(f"{lang}: URLs are not allowed in the text: {s[:80]!r}")
            break
    return p


def check_base(a: dict, corpus: str, fact_ids: set[str], fact_numbers: set[str]) -> list[str]:
    """English article against facts and source texts."""
    problems = _shape(a, "en")
    text = "\n".join(article_strings(a))
    src_versions = versions_in(corpus) | fact_numbers
    ncorpus = norm(corpus)
    for i in sorted(ids_in(text) - fact_ids):
        problems.append(f"identifier {i} is not in FACTS; remove it")
    for v in sorted(versions_in(text) - src_versions):
        problems.append(f"version/number {v} does not appear in the sources; remove it or use one that does")
    for c in sorted(codes_in(text)):
        if norm(c) not in ncorpus and not (ids_in(c) or versions_in(c)):
            problems.append(f"`{c}` does not appear verbatim in the sources; remove the backticks or the command")
    if CYRILLIC_RE.search(text):
        problems.append("en: the base article must be in English")
    return problems


def check_translation(en: dict, tr: dict, lang: str) -> list[str]:
    problems = _shape(tr, lang)
    a, b = tokens("\n".join(article_strings(en))), tokens("\n".join(article_strings(tr)))
    for t in sorted(a - b):
        problems.append(f"{lang}: {t} from the English text is missing or changed; keep it exactly")
    for t in sorted(b - a):
        problems.append(f"{lang}: {t} is not in the English text; remove it")
    if bool(en.get("workaround")) != bool(tr.get("workaround")):
        problems.append(f"{lang}: 'workaround' must be present exactly when the English one is")
    if len(tr.get("checks") or []) != len(en.get("checks") or []):
        problems.append(f"{lang}: 'checks' must have the same number of items as the English text")
    body = f"{tr.get('title', '')} {tr.get('summary', '')}"
    letters = len(LATIN_RE.findall(body)) + len(CYRILLIC_RE.findall(body))
    if lang == "ru" and letters and len(CYRILLIC_RE.findall(body)) / letters < 0.4:
        problems.append("ru: the text is not in Russian")
    if lang == "de":
        if norm(body) == norm(f"{en.get('title', '')} {en.get('summary', '')}") or not GERMAN_HINT_RE.search(body):
            problems.append("de: the text is not in German")
    return problems


def grounded_evidence(evidence: str, corpus: str) -> bool:
    """An extracted fact must quote the sources (whitespace/case-insensitive)."""
    e = norm(evidence)
    return len(e) >= 4 and e in norm(corpus)


def versions_grounded(values: Iterable[str], corpus: str) -> bool:
    src = versions_in(corpus)
    return all(versions_in(v) <= src for v in values if v)
