#!/usr/bin/env python3
# flagscan.py — read-only scan for ARTEMIS{...} flags in files, including base64-encoded ones (up to 3 layers).
# Usage: python3 flagscan.py [dir ...]     (defaults to the usual hiding places; run as root for full access)
import base64, binascii, os, re, stat, sys

roots = sys.argv[1:] or ["/etc", "/var/www", "/opt", "/home", "/root", "/tmp", "/var/tmp", "/usr/local", "/srv"]
tokens = re.compile(rb"[A-Za-z0-9+/_-]{12,}={0,2}")
flags = re.compile(rb"ARTEMIS\{[^{}\r\n]{1,300}\}", re.I)
seen = set()

def b64(token):
    pad = token + b"=" * (-len(token) % 4)
    for fn in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            return fn(pad)
        except (binascii.Error, ValueError):
            continue
    return None

def scan(data, path, depth=0):
    for m in flags.finditer(data):
        key = (path, m.group())
        if key not in seen:
            seen.add(key)
            print(f"{path} [Base64 layers: {depth}] {m.group()!r}", flush=True)
    if depth >= 3:
        return
    for m in tokens.finditer(data):
        t = m.group()
        if len(t) > 100000:
            continue
        d = b64(t)
        if d:
            scan(d, path, depth + 1)

for root in roots:
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in files:
            path = os.path.join(directory, name)
            try:
                info = os.lstat(path)
                if not stat.S_ISREG(info.st_mode) or info.st_size > 10 * 1024 * 1024:
                    continue
                with open(path, "rb") as f:
                    scan(f.read(), path)
            except OSError:
                pass
print("Scan complete.", flush=True)
