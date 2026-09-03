#!/usr/bin/env python3
"""One-way conversion of USNOCTURNE90/Surge rules into sing-box rule-set JSON."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

SURGE_REPOSITORY = "https://github.com/USNOCTURNE90/Surge.git"
SURGE_BRANCH = "Surge"
SIMPLE_TYPES = {
    "DOMAIN": "domain",
    "DOMAIN-SUFFIX": "domain_suffix",
    "DOMAIN-KEYWORD": "domain_keyword",
    "IP-CIDR": "ip_cidr",
    "IP-CIDR6": "ip_cidr",
    "IP-ASN": "ip_asn",
}
ANDROID_PACKAGE = re.compile(r"^(?:com|org|net|io|cn)\.[A-Za-z0-9_.-]+$")
BARE_IPV4 = re.compile(r"^\d+\.\d+\.\d+\.\d+(?:/\d+)?$")
EXCLUDED_NAMES = {"LICENSE", "README", "README.md"}
EXCLUDED_SUFFIXES = {".json", ".md", ".py", ".yml", ".yaml"}


def append_unique(items: list[str], value: str) -> None:
    if value and value not in items:
        items.append(value)


def parse_surge_rules(text: str, source_name: str) -> dict | None:
    simple = {field: [] for field in SIMPLE_TYPES.values()}
    process_names: list[str] = []
    package_names: list[str] = []
    unsupported: list[tuple[int, str]] = []

    for line_number, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [part.strip() for part in line.split(",")]
        rule_type = parts[0].upper()

        if rule_type in SIMPLE_TYPES and len(parts) >= 2:
            append_unique(simple[SIMPLE_TYPES[rule_type]], parts[1])
            continue

        if rule_type == "PROCESS-NAME" and len(parts) >= 2:
            value = parts[1]
            # Historical metadata accidentally normalized as PROCESS-NAME,#,...
            # has no functional match in Surge and must not become a sing-box rule.
            if value == "#":
                continue
            if ANDROID_PACKAGE.fullmatch(value):
                append_unique(package_names, value)
            else:
                append_unique(process_names, value)
            continue

        if BARE_IPV4.fullmatch(line):
            append_unique(simple["ip_cidr"], line if "/" in line else f"{line}/32")
            continue

        unsupported.append((line_number, line))

    if unsupported:
        details = "\n".join(f"  {source_name}:{number}: {line}" for number, line in unsupported)
        raise ValueError(f"Unsupported Surge rule syntax; refusing partial sync:\n{details}")

    rules: list[dict] = []
    simple_rule = {key: values for key, values in simple.items() if values}
    if simple_rule:
        rules.append(simple_rule)
    if process_names:
        rules.append({"process_name": process_names})
    if package_names:
        rules.append({"package_name": package_names})
    return {"version": 1, "rules": rules} if rules else None


def source_files(source_dir: Path) -> list[Path]:
    return sorted(
        path
        for path in source_dir.iterdir()
        if path.is_file()
        and path.name not in EXCLUDED_NAMES
        and path.suffix.lower() not in EXCLUDED_SUFFIXES
    )


def convert_directory(source_dir: Path, target_dir: Path, check: bool = False) -> int:
    changed = 0
    processed = 0
    for source in source_files(source_dir):
        result = parse_surge_rules(source.read_text(encoding="utf-8-sig"), source.name)
        if result is None:
            continue
        processed += 1
        rendered = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
        target = target_dir / f"{source.name}.json"
        current = target.read_text(encoding="utf-8") if target.exists() else None
        if current != rendered:
            changed += 1
            if not check:
                target.write_text(rendered, encoding="utf-8")
            print(("Would update" if check else "Updated") + f": {target.name}")
    print(f"Processed {processed} rule sets; changed {changed}.")
    return changed


def clone_surge(destination: Path) -> None:
    subprocess.run(
        ["git", "clone", "--depth=1", "--branch", SURGE_BRANCH, SURGE_REPOSITORY, str(destination)],
        check=True,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-dir", type=Path)
    parser.add_argument("--target-dir", type=Path, default=Path.cwd())
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    if args.source_dir:
        convert_directory(args.source_dir, args.target_dir, args.check)
        return 0

    temporary_root = Path(tempfile.mkdtemp(prefix="surge-to-singbox-"))
    try:
        source_dir = temporary_root / "Surge"
        clone_surge(source_dir)
        convert_directory(source_dir, args.target_dir, args.check)
    finally:
        shutil.rmtree(temporary_root, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())