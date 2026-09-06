#!/usr/bin/env python3
"""Prepare existing sing-box JSON for URL use; does not parse Surge rules."""

import argparse
import copy
import ipaddress
import json
from pathlib import Path
from urllib.request import Request, urlopen

DOMAIN_FIELDS = ("domain", "domain_suffix", "domain_keyword", "domain_regex")
# Surge's built-in SYSTEM membership; keep it separate from built-in LAN.
SYSTEM_DOMAINS = [
    "api.smoot.apple.com", "captive.apple.com", "xp.apple.com",
    "configuration.apple.com", "guzzoni.apple.com", "smp-device-content.apple.com",
    "aod.itunes.apple.com", "mesu.apple.com", "api.smoot.apple.cn",
    "gs-loc.apple.com", "mvod.itunes.apple.com", "streamingaudio.itunes.apple.com",
]
SYSTEM_SUFFIXES = [
    "ess.apple.com", "push-apple.com.akadns.net", "push.apple.com",
    "lcdn-locator.apple.com", "lcdn-registration.apple.com", "ls.apple.com",
]


def unique(values):
    return list(dict.fromkeys(values))


def active_prefixes(payload):
    if payload.get("status") != "ok":
        raise ValueError("RIPE query failed; do not publish partial ASN rules")
    data = payload["data"]
    end = data["query_endtime"]
    prefixes = {
        str(ipaddress.ip_network(entry["prefix"]))
        for entry in data["prefixes"]
        if any(span["endtime"] == end for span in entry["timelines"])
    }
    if not prefixes:
        raise ValueError("Empty ASN response; keep the previously published rules")
    return sorted(prefixes)


def fetch_asn(asn):
    number = str(asn).removeprefix("AS")
    if not number.isdecimal():
        raise ValueError("Invalid ASN")
    url = "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS" + number
    request = Request(url, headers={"User-Agent": "USNOCTURNE90-sing-box-rules"})
    with urlopen(request, timeout=30) as response:
        return active_prefixes(json.load(response))


def domain_projection(document):
    fields = {}
    for rule in document["rules"]:
        if "type" in rule or "rules" in rule:
            raise ValueError("Logical rule needs explicit DNS projection; refusing to flatten it")
        for key in DOMAIN_FIELDS:
            if key in rule:
                fields[key] = unique(fields.get(key, []) + rule[key])
    return {"version": 1, "rules": [fields] if fields else []}


def prepare(documents, lookup=fetch_asn):
    proxy = copy.deepcopy(documents["USproxyRules.json"])
    asn_cache = {}
    for rule in proxy["rules"]:
        for asn in rule.pop("ip_asn", []):
            if asn not in asn_cache:
                asn_cache[asn] = lookup(asn)
            if not asn_cache[asn]:
                raise ValueError("ASN must not silently disappear")
            for prefix in asn_cache[asn]:
                ipaddress.ip_network(prefix)
            rule["ip_cidr"] = unique(rule.get("ip_cidr", []) + asn_cache[asn])

    lan = copy.deepcopy(documents["LAN.json"])
    for rule in lan["rules"]:
        for key, system_values in [("domain", SYSTEM_DOMAINS), ("domain_suffix", SYSTEM_SUFFIXES)]:
            if key in rule:
                rule[key] = [value for value in rule[key] if value not in system_values]
                if not rule[key]:
                    del rule[key]
    lan["rules"] = [rule for rule in lan["rules"] if rule]

    return {
        "USproxyRules.json": proxy,
        "USproxyRules-domain.json": domain_projection(proxy),
        "MyDirectRules-domain.json": domain_projection(documents["MyDirectRules.json"]),
        "LAN.json": lan,
        "SYSTEM.json": {"version": 1, "rules": [
            {"domain": SYSTEM_DOMAINS, "domain_suffix": SYSTEM_SUFFIXES},
            {"process_name": ["trustd", "netbiosd"]},
        ]},
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=Path, default=Path.cwd())
    args = parser.parse_args()
    directory = args.directory.resolve()
    names = ("USproxyRules.json", "MyDirectRules.json", "LAN.json")
    documents = {name: json.loads((directory / name).read_text(encoding="utf-8")) for name in names}
    # Build all outputs before any write; network/format failure leaves originals untouched.
    outputs = prepare(documents)
    for name, document in outputs.items():
        target = directory / name
        text = json.dumps(document, ensure_ascii=False, indent=2) + "\n"
        if not target.exists() or target.read_text(encoding="utf-8") != text:
            target.write_text(text, encoding="utf-8")
            print("Updated: " + name)


if __name__ == "__main__":
    main()
