"""Text helpers: HTML → plain text, identifier extraction, dates. Source text is untrusted data."""

from __future__ import annotations

import hashlib
import html
import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from html.parser import HTMLParser
from typing import Optional

from .models import Identifiers, Severity

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
KB_RE = re.compile(r"\bKB\d{6,8}\b")
ADVISORY_RES = [
    re.compile(r"\bFG-IR-\d{2}-\d{3,}\b"),  # Fortinet
    re.compile(r"\bUSN-\d{3,5}-\d+\b"),  # Ubuntu
    re.compile(r"\bDSA-\d{3,5}-\d+\b"),  # Debian
    re.compile(r"\bRHSA-\d{4}:\d{3,6}\b"),  # Red Hat
    re.compile(r"\bVMSA-\d{4}-\d{4}\b"),  # VMware
    re.compile(r"\bcisco-sa-[A-Za-z0-9-]+\b"),  # Cisco
    re.compile(r"\bGHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}\b"),  # GitHub
    re.compile(r"\bCTX\d{6}\b"),  # Citrix
    re.compile(r"\bPAN-SA-\d{4}-\d{4}\b"),  # Palo Alto
]
MAX_TEXT = 4000


class _Strip(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.out: list[str] = []
        self.skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self.skip += 1
        elif tag in ("p", "br", "li", "div", "tr", "h1", "h2", "h3", "h4"):
            self.out.append("\n")

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self.skip:
            self.skip -= 1

    def handle_data(self, data):
        if not self.skip:
            self.out.append(data)


def plain(s: Optional[str], limit: int = MAX_TEXT) -> str:
    """HTML or entity-encoded text → plain text, whitespace-normalised, truncated."""
    if not s:
        return ""
    p = _Strip()
    p.feed(html.unescape(s) if "&lt;" in s else s)
    p.close()
    text = "".join(p.out)
    text = re.sub(r"[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f‪-‮⁦-⁩]", "", text)
    text = re.sub(r"[ \t ]+", " ", text)
    text = re.sub(r"\s*\n\s*", "\n", text).strip()
    return text[:limit]


def identifiers(*texts: Optional[str]) -> Identifiers:
    blob = "\n".join(t for t in texts if t)
    ids = Identifiers(
        cve=sorted({m.upper() for m in CVE_RE.findall(blob)}),
        kb=sorted(set(KB_RE.findall(blob))),
        advisory=sorted({m for r in ADVISORY_RES for m in r.findall(blob)}),
    )
    return ids


def severity_from_score(score: Optional[float]) -> Optional[Severity]:
    if score is None:
        return None
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low" if score > 0 else "info"


def severity_word(s: Optional[str]) -> Optional[Severity]:
    if not s:
        return None
    s = s.strip().lower()
    return {
        "critical": "critical", "kritisch": "critical",
        "high": "high", "important": "high",
        "medium": "medium", "moderate": "medium",
        "low": "low", "informational": "info", "info": "info", "none": "info",
    }.get(s)


def parse_date(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    s = s.strip()
    try:
        d = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        try:
            d = parsedate_to_datetime(s)
        except (TypeError, ValueError):
            return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return d.astimezone(timezone.utc).replace(microsecond=0)


def checksum(*parts: object) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(repr(p).encode("utf-8"))
        h.update(b"\x00")
    return h.hexdigest()[:24]


_STOP = {"the", "a", "an", "in", "of", "for", "and", "to", "on", "with", "via", "vulnerability", "vulnerabilities",
         "security", "update", "issue", "multiple", "affecting", "cisco", "products"}


def tokens(s: str) -> set[str]:
    return {w for w in re.findall(r"[a-z0-9][a-z0-9.\-]+", s.lower()) if w not in _STOP and len(w) > 2}


def similarity(a: str, b: str) -> float:
    ta, tb = tokens(a), tokens(b)
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / len(ta | tb)
