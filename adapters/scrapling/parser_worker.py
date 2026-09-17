#!/usr/bin/env python3
"""Static, no-fetch Scrapling parser worker for Sovereign M7-T02.

The worker reads already-acquired HTML bytes from stdin and emits one bounded JSON
record. It intentionally imports only Scrapling's base Selector parser. Fetcher and
browser modules are treated as a contract violation if they become loaded.
"""

from __future__ import annotations

import json
import sys

from scrapling import __version__ as scrapling_version
from scrapling.parser import Selector


FORBIDDEN_PREFIXES = (
    "scrapling.fetchers",
    "scrapling.engines._browsers",
    "playwright",
    "patchright",
    "browserforge",
)
MAX_TEXT_CHARS = 64 * 1024
MAX_LINKS = 128
MAX_LINK_CHARS = 2048


def extras_loaded() -> bool:
    return any(
        name == prefix or name.startswith(prefix + ".")
        for name in sys.modules
        for prefix in FORBIDDEN_PREFIXES
    )


def main() -> int:
    if extras_loaded():
        raise RuntimeError("fetcher/browser extras were loaded before static parsing")

    html = sys.stdin.buffer.read()
    selector = Selector(html, adaptive=False)
    title = selector.css("title::text").get()
    body_text = selector.xpath("//body//text()").getall()
    text = " ".join(part.strip() for part in body_text if part.strip())[:MAX_TEXT_CHARS]
    links = [
        link[:MAX_LINK_CHARS]
        for link in selector.css("a::attr(href)").getall()[:MAX_LINKS]
        if isinstance(link, str)
    ]

    payload = {
        "parser_version": str(scrapling_version),
        "title": title if isinstance(title, str) else None,
        "text": text,
        "links": links,
        "fetcher_or_browser_modules_loaded": extras_loaded(),
    }
    sys.stdout.write(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
