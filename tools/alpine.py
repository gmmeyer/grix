#!/usr/bin/env python3
"""Assemble a directory of Alpine Linux (aarch64) packages plus their
dependencies, ready to import into a grix sandbox.

    tools/alpine.py --out build/python python3
    grix run -a threads -i build/python:/ -- /usr/bin/python3 -c 'print(42)'

Packages come from the official Alpine CDN over HTTPS. Each .apk's control
section is checked against the SHA-1 recorded in the repository index, and
downloads are cached in ~/.cache/grix/alpine.
"""

import argparse
import base64
import hashlib
import io
import os
import sys
import tarfile
import urllib.request
import zlib

RELEASE = "v3.22"
ARCH = "aarch64"
REPOS = ["main", "community"]
MIRROR = "https://dl-cdn.alpinelinux.org/alpine"
CACHE = os.path.expanduser("~/.cache/grix/alpine")


def fetch(url, path):
    if not os.path.exists(path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".part"
        with urllib.request.urlopen(url) as r, open(tmp, "wb") as f:
            f.write(r.read())
        os.replace(tmp, path)
    with open(path, "rb") as f:
        return f.read()


def gzip_members(data):
    """Split concatenated gzip streams; returns (raw member bytes, decompressed)."""
    out = []
    while data:
        d = zlib.decompressobj(31)
        plain = d.decompress(data)
        used = len(data) - len(d.unused_data)
        out.append((data[:used], plain))
        data = d.unused_data
    return out


def cache():
    # aarch64's packages are where they always were; others by architecture.
    return f"{CACHE}/{RELEASE}" + ("" if ARCH == "aarch64" else f"/{ARCH}")


def load_index():
    pkgs, provides = {}, {}
    for repo in REPOS:
        raw = fetch(f"{MIRROR}/{RELEASE}/{repo}/{ARCH}/APKINDEX.tar.gz",
                    f"{cache()}/{repo}/APKINDEX.tar.gz")
        with tarfile.open(fileobj=io.BytesIO(raw)) as t:
            text = t.extractfile("APKINDEX").read().decode()
        for block in text.split("\n\n"):
            fields = {}
            for line in block.splitlines():
                if len(line) > 2 and line[1] == ":":
                    fields.setdefault(line[0], line[2:])
            if "P" not in fields:
                continue
            fields["repo"] = repo
            name = fields["P"]
            pkgs.setdefault(name, fields)
            for prov in fields.get("p", "").split():
                provides.setdefault(prov.split("=")[0], name)
    return pkgs, provides


def resolve(names, pkgs, provides):
    order, seen = [], set()

    def visit(dep):
        if dep.startswith("!"):
            return
        dep = dep.split(">")[0].split("<")[0].split("=")[0].split("~")[0]
        name = dep if dep in pkgs else provides.get(dep)
        if name is None:
            sys.exit(f"alpine.py: no package provides {dep!r}")
        if name in seen:
            return
        seen.add(name)
        for d in pkgs[name].get("D", "").split():
            visit(d)
        order.append(name)

    for n in names:
        visit(n)
    return order


def install(name, pkg, out):
    filename = f"{name}-{pkg['V']}.apk"
    data = fetch(f"{MIRROR}/{RELEASE}/{pkg['repo']}/{ARCH}/{filename}",
                 f"{cache()}/{pkg['repo']}/{filename}")
    members = gzip_members(data)
    # Members: [signature,] control, data. The index records SHA-1 of the control member.
    want = pkg.get("C", "")
    control = next((raw for raw, plain in members if b".PKGINFO" in plain[:1024]), None)
    got = "Q1" + base64.b64encode(hashlib.sha1(control or b"").digest()).decode()
    if got != want:
        sys.exit(f"alpine.py: checksum mismatch for {filename}")
    with tarfile.open(fileobj=io.BytesIO(members[-1][1])) as t:
        for m in t.getmembers():
            if m.name.startswith(".") or m.isdev() or m.isfifo():
                continue
            dest = os.path.join(out, os.path.normpath(m.name))
            # Resolve only the parent: dest itself may be a symlink from an earlier run
            # (e.g. bin/sh -> /bin/busybox), which is replaced below, never followed.
            root = os.path.realpath(out)
            parent = os.path.realpath(os.path.dirname(dest))
            if os.path.basename(dest) in ("", ".", "..") or not (
                    parent == root or parent.startswith(root + os.sep)):
                sys.exit(f"alpine.py: {filename} has unsafe path {m.name!r}")
            if not m.isdir() and os.path.islink(dest):
                os.remove(dest)
            if m.isdir():
                os.makedirs(dest, exist_ok=True)
            elif m.issym():
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                if os.path.lexists(dest):
                    os.remove(dest)
                os.symlink(m.linkname, dest)
            elif m.islnk():
                src = os.path.join(out, m.linkname)
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                with open(src, "rb") as s, open(dest, "wb") as d:
                    d.write(s.read())
                os.chmod(dest, m.mode & 0o777)
            elif m.isfile():
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                with t.extractfile(m) as s, open(dest, "wb") as d:
                    d.write(s.read())
                os.chmod(dest, m.mode & 0o777)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", required=True, help="directory to install into")
    ap.add_argument("--arch", default="aarch64", help="Alpine architecture (aarch64, x86_64)")
    ap.add_argument("packages", nargs="+")
    args = ap.parse_args()
    global ARCH
    ARCH = args.arch
    pkgs, provides = load_index()
    order = resolve(args.packages, pkgs, provides)
    os.makedirs(args.out, exist_ok=True)
    for name in order:
        install(name, pkgs[name], args.out)
    print(f"installed {len(order)} packages into {args.out}: {' '.join(order)}")


if __name__ == "__main__":
    main()
