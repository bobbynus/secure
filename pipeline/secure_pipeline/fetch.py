"""Outbound HTTP for collectors.

- only hosts that appear in the source catalog (plus explicit API hosts) are reachable, redirects included;
- timeouts, bounded retries with backoff (5xx, 429, network), Retry-After honoured up to a cap;
- response size limit; conditional GET (ETag / Last-Modified).
Downloaded documents are untrusted data: they are parsed, never executed.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from typing import Iterable, Optional
from urllib.parse import urljoin, urlsplit

import httpx

USER_AGENT = "secure.abramov.vip-collector/1.0 (+https://secure.abramov.vip/en/sources/)"
TIMEOUT = httpx.Timeout(30.0, connect=10.0)
MAX_BYTES = 40 * 1024 * 1024
RETRIES = 3
MAX_REDIRECTS = 5


class FetchError(Exception):
    pass


@dataclass
class Response:
    status: int
    url: str
    body: bytes
    etag: Optional[str]
    last_modified: Optional[str]
    content_type: str

    @property
    def not_modified(self) -> bool:
        return self.status == 304

    def checksum(self) -> str:
        return hashlib.sha256(self.body).hexdigest()

    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


class Fetcher:
    def __init__(self, allowed_hosts: Iterable[str], client: Optional[httpx.Client] = None, sleep=time.sleep):
        self.allowed = {h.lower() for h in allowed_hosts}
        self.client = client or httpx.Client(timeout=TIMEOUT, headers={"User-Agent": USER_AGENT}, follow_redirects=False)
        self.sleep = sleep

    def close(self):
        self.client.close()

    def _check(self, url: str):
        parts = urlsplit(url)
        if parts.scheme != "https":
            raise FetchError(f"blocked scheme: {url}")
        if (parts.hostname or "").lower() not in self.allowed:
            raise FetchError(f"blocked host: {parts.hostname}")

    def get(self, url: str, *, etag: Optional[str] = None, last_modified: Optional[str] = None,
            headers: Optional[dict[str, str]] = None, max_bytes: int = MAX_BYTES) -> Response:
        h = dict(headers or {})
        if etag:
            h["If-None-Match"] = etag
        if last_modified:
            h["If-Modified-Since"] = last_modified
        attempt = 0
        while True:
            attempt += 1
            try:
                return self._get_once(url, h, max_bytes)
            except _Retryable as e:
                if attempt > RETRIES:
                    raise FetchError(f"{url}: {e}") from None
                self.sleep(min(e.wait or 2 ** attempt, 60))
            except httpx.TransportError as e:
                if attempt > RETRIES:
                    raise FetchError(f"{url}: {type(e).__name__}") from None
                self.sleep(2 ** attempt)

    def _get_once(self, url: str, headers: dict[str, str], max_bytes: int) -> Response:
        for _ in range(MAX_REDIRECTS + 1):
            self._check(url)
            with self.client.stream("GET", url, headers=headers) as r:
                if r.status_code in (301, 302, 303, 307, 308):
                    loc = r.headers.get("Location")
                    if not loc:
                        raise FetchError(f"redirect without location: {url}")
                    url = urljoin(url, loc)
                    continue
                if r.status_code == 429 or r.status_code >= 500:
                    raise _Retryable(f"HTTP {r.status_code}", _retry_after(r.headers.get("Retry-After")))
                if r.status_code == 304:
                    return Response(304, url, b"", r.headers.get("ETag"), r.headers.get("Last-Modified"), "")
                if r.status_code != 200:
                    raise FetchError(f"{url}: HTTP {r.status_code}")
                declared = int(r.headers.get("Content-Length") or 0)
                if declared > max_bytes:
                    raise FetchError(f"{url}: too large ({declared} bytes)")
                chunks, size = [], 0
                for chunk in r.iter_bytes():
                    size += len(chunk)
                    if size > max_bytes:
                        raise FetchError(f"{url}: too large (> {max_bytes} bytes)")
                    chunks.append(chunk)
                return Response(200, url, b"".join(chunks), r.headers.get("ETag"), r.headers.get("Last-Modified"),
                                r.headers.get("Content-Type", ""))
        raise FetchError(f"{url}: too many redirects")


class _Retryable(Exception):
    def __init__(self, msg: str, wait: Optional[float] = None):
        super().__init__(msg)
        self.wait = wait


def _retry_after(v: Optional[str]) -> Optional[float]:
    try:
        return float(v) if v else None
    except ValueError:
        return None
