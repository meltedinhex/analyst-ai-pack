#!/usr/bin/env python3
"""Cluster suspected adversary infrastructure on shared pivot attributes.

Groups host records that share values for one or more chosen attributes (e.g., JARM, cert CN,
favicon hash, ASN) and ranks clusters by the count of distinct shared attributes. Defangs host
indicators. Parses data only; executes nothing.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

GENERIC_VALUES = {"", "none", "null", "cloudflare", "n/a"}


def _defang(host: str) -> str:
    return host.replace(".", "[.]")


def cluster(path: str, attrs: list[str]) -> dict:
    hosts = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    # Map (attr, value) -> set of host ids.
    groups: dict[tuple, set] = defaultdict(set)
    host_label = {}
    for i, h in enumerate(hosts):
        hid = h.get("host") or h.get("ip") or str(i)
        host_label[hid] = hid
        for a in attrs:
            val = str(h.get(a, "")).strip().lower()
            if val and val not in GENERIC_VALUES:
                groups[(a, val)].add(hid)
    # Build host->shared-attribute links, then connected clusters via shared keys.
    host_attrs: dict[str, set] = defaultdict(set)
    for (a, val), members in groups.items():
        if len(members) >= 2:
            for m in members:
                host_attrs[m].add((a, val))
    # Union-find over hosts sharing any (attr,value).
    parent: dict[str, str] = {h: h for h in host_attrs}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for members in groups.values():
        members = [m for m in members if m in parent]
        for m in members[1:]:
            parent[find(m)] = find(members[0])
    clusters: dict[str, set] = defaultdict(set)
    for h in host_attrs:
        clusters[find(h)].add(h)
    result = []
    for members in clusters.values():
        shared = set.intersection(*[host_attrs[m] for m in members]) if members else set()
        result.append({
            "hosts": sorted(_defang(m) for m in members),
            "shared_attributes": sorted(f"{a}={v}" for a, v in shared),
            "strength": len(shared),
        })
    result.sort(key=lambda d: (d["strength"], len(d["hosts"])), reverse=True)
    return {"clusters": result, "cluster_count": len(result)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Cluster adversary infrastructure")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("cluster")
    p.add_argument("hosts")
    p.add_argument("--attrs", required=True, help="comma list, e.g. jarm,cert_cn,asn")
    args = parser.parse_args(argv)
    print(json.dumps(cluster(args.hosts, [a.strip() for a in args.attrs.split(",")]), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
