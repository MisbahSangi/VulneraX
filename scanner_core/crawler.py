import json
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from collections import deque
from typing import List, Dict, Set, Tuple
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_PATH = BASE_DIR / "config" / "settings.json"


def load_config():
    cfg = {
        "crawler": {
            "max_pages": 30,
            "max_depth": 3,
            "request_timeout": 10,
        }
    }
    try:
        with CONFIG_PATH.open("r", encoding="utf-8") as f:
            user_cfg = json.load(f)
        crawler_cfg = user_cfg.get("crawler", {})
        cfg["crawler"].update(crawler_cfg)
    except Exception:
        # Use defaults if config missing or invalid
        pass
    return cfg


_CONFIG = load_config()
_REQUEST_TIMEOUT = _CONFIG["crawler"]["request_timeout"]
_MAX_PAGES_DEFAULT = _CONFIG["crawler"]["max_pages"]
_MAX_DEPTH_DEFAULT = _CONFIG["crawler"]["max_depth"]


def get_all_links(url: str) -> Set[str]:
    """
    Fetch a page and return all internal links (same domain).
    """
    links: Set[str] = set()
    try:
        response = requests.get(url, timeout=_REQUEST_TIMEOUT)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, "html.parser")

        base_netloc = urlparse(url).netloc

        for a_tag in soup.find_all("a", href=True):
            href = a_tag["href"]
            full_url = urljoin(url, href)

            parsed = urlparse(full_url)

            # Only HTTP/HTTPS and same domain
            if parsed.scheme in ("http", "https") and parsed.netloc == base_netloc:
                # Normalize: remove fragments (#something)
                normalized = full_url.split("#")[0]
                links.add(normalized)

    except Exception as e:
        print(f"[!] Error fetching links from {url}: {e}")

    return links


def get_all_forms(url: str):
    """
    Fetch a page and return all <form> elements (BeautifulSoup objects).
    """
    try:
        response = requests.get(url, timeout=_REQUEST_TIMEOUT)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, "html.parser")
        return soup.find_all("form")
    except Exception as e:
        print(f"[!] Error fetching forms from {url}: {e}")
        return []


def parse_forms(url: str) -> List[Dict]:
    """
    Turn raw <form> tags on a page into a simpler Python structure.
    """
    forms_info: List[Dict] = []
    forms = get_all_forms(url)

    for form in forms:
        action = form.get("action") or url
        method = (form.get("method") or "GET").upper()

        action_url = urljoin(url, action)

        inputs = []
        for input_tag in form.find_all(["input", "textarea", "select"]):
            name = input_tag.get("name")
            if name:
                inputs.append(name)

        forms_info.append(
            {
                "page_url": url,
                "action": action_url,
                "method": method,
                "inputs": inputs,
            }
        )

    return forms_info


def crawl_site(start_url: str, max_pages: int | None = None, max_depth: int | None = None) -> List[Dict]:
    """
    Breadth‑first crawl starting from `start_url`.

    Limits:
      - max_pages: maximum number of pages to visit.
      - max_depth: maximum link depth from the start URL.
    """
    if max_pages is None:
        max_pages = _MAX_PAGES_DEFAULT
    if max_depth is None:
        max_depth = _MAX_DEPTH_DEFAULT

    visited: Set[str] = set()
    queue: deque[Tuple[str, int]] = deque([(start_url, 0)])
    pages: List[Dict] = []

    base_netloc = urlparse(start_url).netloc

    while queue and len(visited) < max_pages:
        current, depth = queue.popleft()
        if current in visited:
            continue

        visited.add(current)
        print(f"[*] Crawling: {current} (depth={depth})")

        try:
            response = requests.get(current, timeout=_REQUEST_TIMEOUT)
            response.raise_for_status()
            soup = BeautifulSoup(response.content, "html.parser")

            page_links: Set[str] = set()
            if depth < max_depth:
                for a_tag in soup.find_all("a", href=True):
                    href = a_tag["href"]
                    full_url = urljoin(current, href)
                    parsed = urlparse(full_url)

                    if parsed.scheme in ("http", "https") and parsed.netloc == base_netloc:
                        normalized = full_url.split("#")[0]
                        page_links.add(normalized)
                        if normalized not in visited:
                            queue.append((normalized, depth + 1))

            forms = parse_forms(current)

            pages.append(
                {
                    "url": current,
                    "links": list(page_links),
                    "forms": forms,
                    "depth": depth,
                }
            )

        except Exception as e:
            print(f"[!] Error crawling {current}: {e}")

    return pages