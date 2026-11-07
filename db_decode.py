#!/usr/bin/env python3
"""db_decode.py — decode the UEFI 'db' variable from a Hyper-V .vmgs NVRAM doc.

Walks the concatenated EFI_SIGNATURE_LISTs and, for every signature, prints the
SignatureOwner and cert metadata (length, leading bytes, sha256, DER sanity),
so you can verify the layout of the firmware's own entries and of any cert you
injected. Optionally byte-compares each cert against reference files.

EFI_SIGNATURE_LIST layout:
    X509_GUID(16) | ListSize(u32le) | HeaderSize(u32le) | SigSize(u32le)
    | [ Owner(16) + cert DER ]  (n signatures, SigSize bytes each)
    ListSize must equal 28 + HeaderSize + n*SigSize and consume the list exactly.

Usage:
  python db_decode.py <vmgs> [--doc 1|2] [--ref cert1.der cert2.der ...]
"""
import argparse
import hashlib
import io
import json
import struct
import sys
from pathlib import Path

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

PREFIX = '{"Version":{"Major":0,"Minor":0},"Devices"'.encode('utf-16-le')
X509_B = bytes.fromhex('a159c0a5e494a74a87b5ab155c2bf072')


def find_docs(buf):
    docs = []
    idx = 0
    while True:
        pos = buf.find(PREFIX, idx)
        if pos < 0:
            break
        if pos % 2:
            idx = pos + 1
            continue
        text = buf[pos:].decode('utf-16-le', errors='replace')
        depth = 0
        ins = False
        esc = False
        end = -1
        for i, c in enumerate(text):
            if ins:
                if esc:
                    esc = False
                elif c == '\\':
                    esc = True
                elif c == '"':
                    ins = False
            else:
                if c == '"':
                    ins = True
                elif c == '{':
                    depth += 1
                elif c == '}':
                    depth -= 1
                    if depth == 0:
                        end = i
                        break
        if end < 0:
            idx = pos + 1
            continue
        docs.append((pos, text[:end + 1]))
        idx = pos + 2 * (end + 1)
        if len(docs) >= 4:
            break
    return docs


def find_db(x):
    if isinstance(x, dict):
        for k, v in x.items():
            if k == 'db' and isinstance(v, dict) and 'Data' in v:
                return v
            r = find_db(v)
            if r:
                return r
    elif isinstance(x, list):
        for v in x:
            r = find_db(v)
            if r:
                return r
    return None


def main():
    ap = argparse.ArgumentParser(description='Decode the UEFI db variable in a Hyper-V .vmgs file.')
    ap.add_argument('vmgs', help='path to the .vmgs file')
    ap.add_argument('--doc', type=int, choices=(1, 2), default=1,
                    help='which redundant NVRAM doc to read (default 1)')
    ap.add_argument('--ref', nargs='*', default=[],
                    help='reference cert DER files to byte-compare against')
    a = ap.parse_args()

    orig = Path(a.vmgs).read_bytes()
    docs = find_docs(orig)
    if len(docs) < a.doc:
        sys.exit('doc %d not found (found %d docs)' % (a.doc, len(docs)))
    text = docs[a.doc - 1][1]
    o = json.loads(text)
    dbv = find_db(o)
    if not dbv:
        sys.exit('no db variable in doc%d' % a.doc)
    db = bytes(dbv['Data'])
    print('doc%d db: attrs=%s len=%d head=%s' % (a.doc, dbv['Attributes'], len(db), db[:16].hex()))

    refs = {}
    for p in a.ref:
        refs[str(Path(p))] = Path(p).read_bytes()

    off, li = 0, 0
    while off < len(db):
        if off + 28 > len(db):
            print('!!! list header overruns at %d' % off)
            break
        stype = db[off:off + 16]
        ls = struct.unpack_from('<I', db, off + 16)[0]
        hs = struct.unpack_from('<I', db, off + 20)[0]
        ss = struct.unpack_from('<I', db, off + 24)[0]
        print('--- list %d @%d: type=%s ListSize=%d HeaderSize=%d SigSize=%d %s'
              % (li, off, stype.hex(), ls, hs, ss,
                 '(X509)' if stype == X509_B else ''))
        data_start = off + 28 + hs
        s, si = data_start, 0
        while s + ss <= off + ls:
            owner = db[s:s + 16]
            cert = db[s + 16:s + ss]
            print('    sig %d: owner=%s' % (si, owner.hex()))
            print('           cert_len=%d first4=%s sha256=%s  DER-ok(0x30)=%s'
                  % (len(cert), cert[:4].hex(), hashlib.sha256(cert).hexdigest()[:16],
                     cert[:1] == b'\x30'))
            for name, rb in refs.items():
                if cert == rb:
                    print('           >>> MATCHES %s' % name)
            s += ss
            si += 1
        print('    sigs=%d  exact-fit-to-ListSize=%s' % (si, s == off + ls))
        off += ls
        li += 1
    print('walked all: off=%d == db len (%d)? %s' % (off, len(db), off == len(db)))


if __name__ == '__main__':
    main()
