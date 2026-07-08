#!/usr/bin/env python3
"""Extract possible IOCs from a text file."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from urllib.parse import urlparse


PATTERNS = {
    "ipv4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    "urls": re.compile(r"\bhttps?://[^\s<>()\"']+", re.IGNORECASE),
    "emails": re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "domains": re.compile(r"\b(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,}\b", re.IGNORECASE),
}


COMMON_FALSE_POSITIVE_SUFFIXES = {
    ".dll",
    ".doc",
    ".docx",
    ".exe",
    ".html",
    ".jpeg",
    ".jpg",
    ".json",
    ".log",
    ".pdf",
    ".png",
    ".ppt",
    ".pptx",
    ".txt",
    ".xls",
    ".xlsx",
    ".xml",
    ".zip",
}


def normalize_url(value: str) -> str:
    return value.rstrip(".,;)]}")


def extract_domains_from_urls(urls: list[str]) -> set[str]:
    domains: set[str] = set()
    for url in urls:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if hostname:
            domains.add(hostname.lower())
    return domains


def looks_like_filename(value: str) -> bool:
    return any(value.lower().endswith(suffix) for suffix in COMMON_FALSE_POSITIVE_SUFFIXES)


def unique_sorted(values: set[str]) -> list[str]:
    return sorted(values, key=lambda item: item.lower())


def extract_iocs(text: str) -> dict[str, list[str]]:
    urls = {normalize_url(match.group(0)) for match in PATTERNS["urls"].finditer(text)}
    domains = {match.group(0).lower() for match in PATTERNS["domains"].finditer(text)}
    domains.update(extract_domains_from_urls(list(urls)))
    domains = {domain for domain in domains if not looks_like_filename(domain)}

    results = {
        "ipv4": {match.group(0) for match in PATTERNS["ipv4"].finditer(text)},
        "urls": urls,
        "domains": domains,
        "emails": {match.group(0).lower() for match in PATTERNS["emails"].finditer(text)},
        "md5": {match.group(0).lower() for match in PATTERNS["md5"].finditer(text)},
        "sha1": {match.group(0).lower() for match in PATTERNS["sha1"].finditer(text)},
        "sha256": {match.group(0).lower() for match in PATTERNS["sha256"].finditer(text)},
    }

    # Avoid classifying SHA-1/SHA-256 values as shorter hashes through overlap.
    results["md5"] = {
        value for value in results["md5"] if value not in results["sha1"] and value not in results["sha256"]
    }
    results["sha1"] = {value for value in results["sha1"] if value not in results["sha256"]}

    return {key: unique_sorted(value) for key, value in results.items()}


def print_text(results: dict[str, list[str]]) -> None:
    for category, values in results.items():
        print(f"[{category}]")
        if values:
            for value in values:
                print(f"- {value}")
        else:
            print("-")
        print()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Extract possible IOCs from a text file.")
    parser.add_argument("file", type=Path, help="Input text file")
    parser.add_argument("--json", action="store_true", help="Print results as JSON")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if not args.file.is_file():
        print(f"ERROR: file not found or not a regular file: {args.file}")
        return 2

    text = args.file.read_text(encoding="utf-8", errors="replace")
    results = extract_iocs(text)

    if args.json:
        print(json.dumps(results, indent=2, ensure_ascii=False))
    else:
        print_text(results)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
