"""Model providers. Swappable: the pipeline only needs `complete_json(system, prompt, schema)`.

Gemini (free tier) via the REST generateContent endpoint:
- paced requests (free tier RPM), bounded retries for 5xx and per-minute 429 with the server's RetryInfo;
- a daily-quota 429 marks the model exhausted and the next model in the list is tried;
- when every model is exhausted `QuotaExhausted` stops the AI step for this run (the queue waits).
The API key is sent as a header and never logged.
"""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Optional, Protocol

import httpx

GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
# The key's Google project quota is shared with other projects of the owner (free tier, 2026-11):
#   gemini-3.5-flash-lite 15 RPM / 250K TPM / 500 RPD;  gemini-3.6-flash 5 RPM / 250K TPM / 20 RPD.
# This pipeline takes a small, fixed share: flash-lite only, <= 4 requests per minute, a daily request budget.
DEFAULT_MODELS = ("gemini-3.5-flash-lite",)
PACIFIC = timezone(timedelta(hours=-8))  # quota day of the Gemini API (PST; DST shifts it by an hour, harmless)


class DailyBudget:
    """Requests sent per quota day, persisted in the state so all runs of a day share one budget."""

    def __init__(self, path: Path, max_requests: int, now: Callable[[], datetime] = lambda: datetime.now(timezone.utc)):
        self.path, self.max, self.now = Path(path), max_requests, now

    def _day(self) -> str:
        return self.now().astimezone(PACIFIC).strftime("%Y-%m-%d")

    def _load(self) -> dict:
        return json.loads(self.path.read_text(encoding="utf-8")) if self.path.exists() else {}

    def used(self) -> int:
        return int(self._load().get(self._day(), {}).get("requests", 0))

    def take(self, tokens: int = 0):
        """Reserve one request; raises QuotaExhausted when today's budget is spent."""
        data = self._load()
        day = self._day()
        row = data.setdefault(day, {"requests": 0, "tokens": 0})
        if row["requests"] >= self.max:
            raise QuotaExhausted(f"local daily budget of {self.max} requests reached")
        row["requests"] += 1
        row["tokens"] += tokens
        data = {k: data[k] for k in sorted(data)[-14:]}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=1), encoding="utf-8")
        os.replace(tmp, self.path)

    def add_tokens(self, tokens: int):
        data = self._load()
        row = data.get(self._day())
        if row is not None:
            row["tokens"] = row.get("tokens", 0) + tokens
            self.path.write_text(json.dumps(data, indent=1), encoding="utf-8")


class ProviderError(Exception):
    pass


class QuotaExhausted(ProviderError):
    pass


class Overloaded(ProviderError):
    """Model busy (503) or rate-limited twice in a row: stop this run, retry next run; not the event's fault."""


@dataclass
class Completion:
    data: dict
    model: str
    usage: dict = field(default_factory=dict)
    latency: float = 0.0
    cached: bool = False


class Provider(Protocol):
    models: list[str]

    def complete_json(self, system: str, prompt: str, schema: dict) -> Completion: ...


def parse_json_text(text: str) -> dict:
    t = text.strip()
    if t.startswith("```"):
        t = re.sub(r"^```(?:json)?\s*|\s*```$", "", t)
    data = json.loads(t)
    if not isinstance(data, dict):
        raise ValueError("model output is not a JSON object")
    return data


class Gemini:
    def __init__(self, api_key: str, models: Optional[list[str]] = None, *, client: Optional[httpx.Client] = None,
                 min_interval: float = 15.0, max_output_tokens: int = 6144, budget: Optional[DailyBudget] = None,
                 sleep: Callable[[float], None] = time.sleep, clock: Callable[[], float] = time.monotonic):
        if not api_key:
            raise ValueError("GEMINI_API_KEY is empty")
        self.key = api_key
        self.models = list(models or DEFAULT_MODELS)
        self.client = client or httpx.Client(timeout=httpx.Timeout(120.0, connect=10.0))
        self.min_interval = min_interval
        self.max_output_tokens = max_output_tokens
        self.sleep, self.clock = sleep, clock
        self.exhausted: set[str] = set()
        self._last = -1e9
        self._compat: set[str] = set()  # models that rejected optional config fields
        self.calls = 0
        self.budget = budget
        self.statuses: dict[int, int] = {}  # non-200 responses, for run logs

    def close(self):
        self.client.close()

    def available(self) -> list[str]:
        return [m for m in self.models if m not in self.exhausted]

    def complete_json(self, system: str, prompt: str, schema: dict, *, models: Optional[list[str]] = None) -> Completion:
        for model in models or self.available():
            if model in self.exhausted:
                continue
            try:
                return self._call(model, system, prompt, schema)
            except QuotaExhausted:
                self.exhausted.add(model)
        raise QuotaExhausted("daily quota exhausted for all models: " + ", ".join(self.models))

    # ------------------------------------------------------------------

    def _body(self, model: str, system: str, prompt: str, schema: dict) -> dict:
        cfg: dict = {"responseMimeType": "application/json", "maxOutputTokens": self.max_output_tokens}
        if model not in self._compat:
            cfg["responseJsonSchema"] = schema
            if model.startswith("gemini-3") or model.startswith("gemini-4"):
                cfg["thinkingConfig"] = {"thinkingLevel": "LOW"}
        return {
            "systemInstruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": cfg,
        }

    def _pace(self):
        wait = self._last + self.min_interval - self.clock()
        if wait > 0:
            self.sleep(wait)
        self._last = self.clock()

    def _call(self, model: str, system: str, prompt: str, schema: dict) -> Completion:
        url = GEMINI_URL.format(model=model)
        for attempt in range(5):
            self._pace()
            if self.budget:
                self.budget.take()
            started = self.clock()
            try:
                r = self.client.post(url, json=self._body(model, system, prompt, schema),
                                     headers={"x-goog-api-key": self.key, "Content-Type": "application/json"})
            except httpx.TransportError as e:
                if attempt >= 3:
                    raise ProviderError(f"{model}: network {type(e).__name__}") from None
                self.sleep(5 * 2 ** attempt)
                continue
            self.calls += 1
            if r.status_code == 200:
                comp = self._parse(model, r, self.clock() - started)
                if self.budget:
                    self.budget.add_tokens(int(comp.usage.get("totalTokenCount") or 0))
                return comp
            err = _error(r)
            if r.status_code == 429:
                if err["daily"]:
                    raise QuotaExhausted(f"{model}: {err['message'][:160]}")
                self.statuses[429] = self.statuses.get(429, 0) + 1
                if attempt >= 1:
                    raise Overloaded(f"{model}: rate limited twice (shared quota busy)")
                self.sleep(min(err["retry"] or 30, 65))
                continue
            if r.status_code in (500, 502, 503, 504):
                self.statuses[r.status_code] = self.statuses.get(r.status_code, 0) + 1
                if attempt >= 1:
                    raise Overloaded(f"{model}: HTTP {r.status_code} {err['message'][:120]}")
                self.sleep(min(err["retry"] or 20, 60))
                continue
            if r.status_code == 400 and model not in self._compat and re.search(
                    r"responseJsonSchema|thinking|Unknown name|schema", err["message"], re.I):
                self._compat.add(model)  # older model or API revision: schema goes in the prompt only
                continue
            if r.status_code == 404:
                raise QuotaExhausted(f"{model}: model not available ({err['message'][:120]})")
            raise ProviderError(f"{model}: HTTP {r.status_code} {err['message'][:200]}")
        raise ProviderError(f"{model}: retries exhausted")

    def _parse(self, model: str, r: httpx.Response, latency: float) -> Completion:
        body = r.json()
        block = (body.get("promptFeedback") or {}).get("blockReason")
        if block:
            raise ProviderError(f"{model}: prompt blocked ({block})")
        cands = body.get("candidates") or []
        if not cands:
            raise ProviderError(f"{model}: no candidates")
        c = cands[0]
        reason = c.get("finishReason", "STOP")
        parts = (c.get("content") or {}).get("parts") or []
        text = "".join(p.get("text", "") for p in parts if not p.get("thought"))
        if reason not in ("STOP", "FINISH_REASON_UNSPECIFIED") or not text:
            raise ProviderError(f"{model}: finishReason {reason}")
        try:
            data = parse_json_text(text)
        except ValueError as e:  # json.JSONDecodeError is a ValueError
            raise ProviderError(f"{model}: invalid JSON ({e})") from None
        u = body.get("usageMetadata") or {}
        usage = {k: u.get(k, 0) for k in ("promptTokenCount", "candidatesTokenCount", "thoughtsTokenCount", "totalTokenCount")}
        return Completion(data=data, model=model, usage=usage, latency=round(latency, 2))


def _error(r: httpx.Response) -> dict:
    out = {"message": f"HTTP {r.status_code}", "daily": False, "retry": None}
    try:
        e = r.json().get("error") or {}
    except ValueError:
        return out
    out["message"] = str(e.get("message") or out["message"]).replace("\n", " ")
    for d in e.get("details") or []:
        t = str(d.get("@type", ""))
        if t.endswith("QuotaFailure"):
            for v in d.get("violations") or []:
                if "PerDay" in str(v.get("quotaId", "")) or "per_day" in str(v.get("quotaMetric", "")).lower():
                    out["daily"] = True
        elif t.endswith("RetryInfo"):
            m = re.match(r"([\d.]+)s", str(d.get("retryDelay", "")))
            if m:
                out["retry"] = float(m.group(1)) + 1
    return out
