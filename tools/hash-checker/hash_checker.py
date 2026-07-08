#!/usr/bin/env python3
"""Calculate file hashes and optionally compare them with an expected value."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


SUPPORTED_ALGORITHMS = {
    "md5": hashlib.md5,
    "sha1": hashlib.sha1,
    "sha256": hashlib.sha256,
    "sha512": hashlib.sha512,
}


def calculate_hash(path: Path, algorithm: str) -> str:
    hasher = SUPPORTED_ALGORITHMS[algorithm]()
    with path.open("rb") as file_obj:
        for chunk in iter(lambda: file_obj.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Calculate a file hash and optionally compare it with an expected value."
    )
    parser.add_argument("file", type=Path, help="File to hash")
    parser.add_argument(
        "--algorithm",
        "-a",
        choices=sorted(SUPPORTED_ALGORITHMS),
        default="sha256",
        help="Hash algorithm to use. Default: sha256",
    )
    parser.add_argument(
        "--expected",
        "-e",
        help="Expected hash value for comparison",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    path = args.file

    if not path.is_file():
        print(f"ERROR: file not found or not a regular file: {path}")
        return 2

    digest = calculate_hash(path, args.algorithm)

    print(f"file: {path}")
    print(f"algorithm: {args.algorithm}")
    print(f"hash: {digest}")

    if args.expected:
        expected = args.expected.strip().lower()
        matches = digest.lower() == expected
        print(f"expected: {expected}")
        print(f"match: {'yes' if matches else 'no'}")
        return 0 if matches else 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
