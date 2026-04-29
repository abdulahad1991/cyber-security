import time
import json
import os
from typing import Any

import requests
from bs4 import BeautifulSoup

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data")


def fetch(url: str, retries: int = 3, delay: float = 1.5, timeout: int = 30) -> requests.Response:
    headers = {"User-Agent": "XennTool-Scraper/1.0 (+https://xenntool.com)"}
    last_err: Exception = RuntimeError("No attempts made")
    for attempt in range(retries):
        try:
            resp = requests.get(url, headers=headers, timeout=timeout)
            resp.raise_for_status()
            return resp
        except requests.RequestException as e:
            last_err = e
            if attempt < retries - 1:
                time.sleep(delay * (2 ** attempt))
    raise last_err


def html_to_text(html: str) -> str:
    soup = BeautifulSoup(html, "lxml")
    for tag in soup(["script", "style", "nav", "footer", "header"]):
        tag.decompose()
    return " ".join(soup.get_text(" ", strip=True).split())


def extract_sections(html: str, heading_tag: str = "h2") -> list[dict]:
    soup = BeautifulSoup(html, "lxml")
    sections = []
    for heading in soup.find_all(heading_tag):
        title = heading.get_text(strip=True)
        parts = []
        for sibling in heading.find_next_siblings():
            if sibling.name == heading_tag:
                break
            text = sibling.get_text(" ", strip=True)
            if text:
                parts.append(text)
        sections.append({"title": title, "content": " ".join(parts)})
    return sections


def write_json(category: str, data: dict[str, Any]) -> str:
    os.makedirs(DATA_DIR, exist_ok=True)
    path = os.path.join(DATA_DIR, f"{category}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    return path
