#!/usr/bin/env python3
"""vmgs_dbinject.py — inject an X.509 certificate into the UEFI 'db' variable
of a Hyper-V Gen 2 VM's .vmgs file (firmware NVRAM), as an appended
EFI_SIGNATURE_LIST, in both redundant NVRAM documents, with valid GUESTRTS
redundancy-header CRCs.

Usage:
  python vmgs_dbinject.py --base <booting.vmgs> --live <live.vmgs> --cert <cert.der>
  python vmgs_dbinject.py --base <booting.vmgs> --live <live.vmgs> --cert <cert.der> --write

Rules of the road:
  * --base must be a .vmgs that is KNOWN TO POWER ON (a clean backup). Always
    rebuild from base; never patch a live file across reboots.
  * The live VM must be OFF while you write its .vmgs.
  * After writing, the change only reaches the firmware after
    `Restart-Service vmms` (VMMS caches NVRAM in memory).
  * The firmware rewrites .vmgs on shutdown / failed boot — rebuild before
    every boot attempt.

Format facts (verified):
  * .vmgs = VMGS v1, 4 MiB (0x400200). GPT at 0x200 / 0x3FFE00 (never touched).
  * NVRAM = two redundant UTF-16LE JSON docs at fixed offsets 0x4800 (doc1)
    and 0x200200 (doc2), each followed by one NUL. Doc =
    {"Version":...,"Devices":{...,"ac6b8dc1-3257-4a70-b1b2-a9c9215659ad"
    (Virtual BIOS):...,"States":{"Nvram":{"Vendors":{<guid>:{"Variables":{
    "db":{"Attributes":39,"Data":[ints]}}}}}}}.
  * 'db' = concatenation of EFI_SIGNATURE_LISTs:
      X509_GUID(16) | ListSize(u32le) | HeaderSize(u32le)=0 | SigSize(u32le)
      | [ Owner(16) + cert DER ]
    SigSize = 16 + cert_len (NOT 32+cert); ListSize = 28 + HeaderSize + n*SigSize.
    GUID bytes in this NVRAM are stored in hex-string order
    (a159c0a5e494a74a...), not EFI little-endian field order.
  * Two 96-byte GUESTRTS redundancy headers: R1 @ 0x4400 (current bank),
    R2 @ 0x4600. S1 @ R1+0x30 and S2 @ R1+0x50 must equal doc_len+2 after an
    edit; cksum @ +0x0C = zlib.crc32(96-byte header with bytes 12..16 zeroed).
    After an edit: update R1 S fields + R1 CRC; R2 stays untouched (its base
    CRC remains valid). BOTH banks must validate.
"""
import argparse
import hashlib
import io
import json
import shutil
import struct
import sys
import time
import zlib
from pathlib import Path

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

VMGS_SIZE = 0x400200
DOC1, DOC2 = 0x4800, 0x200200
R1B, R2B = 0x4400, 0x4600
X509_B = bytes.fromhex('a159c0a5e494a74a87b5ab155c2bf072')
GPT_OFFS = (0x200, 0x3FFE00)
PREFIX = '{"Version":{"Major":0,"Minor":0},"Devices"'.encode('utf-16-le')


def hdr_crc(h96: bytes) -> int:
    z = bytearray(h96)
    z[12:16] = b'\x00' * 4
    return zlib.crc32(bytes(z)) & 0xFFFFFFFF


def find_docs(buf):
    """Locate the redundant NVRAM JSON docs (UTF-16LE) by discovery prefix."""
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
    """Find the 'db' variable anywhere in the doc JSON tree."""
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
    ap = argparse.ArgumentParser(
        description='Inject an X.509 cert into the UEFI db variable of a Hyper-V .vmgs file.')
    ap.add_argument('--base', required=True, help='known-good booting .vmgs (all builds start here)')
    ap.add_argument('--live', required=True, help='live .vmgs to update (VM must be Off)')
    ap.add_argument('--cert', required=True, help='X.509 certificate DER to add to db')
    ap.add_argument('--owner', default=None,
                    help='16-byte SignatureOwner as 32 hex chars (default: all zeros)')
    ap.add_argument('--write', action='store_true', help='write the live file (backs it up first)')
    a = ap.parse_args()

    owner = bytes.fromhex(a.owner) if a.owner else b'\x00' * 16
    if len(owner) != 16:
        sys.exit('owner must be exactly 16 bytes')

    orig = Path(a.base).read_bytes()
    if len(orig) != VMGS_SIZE:
        sys.exit('base is not %d bytes (0x%x)' % (VMGS_SIZE, VMGS_SIZE))
    print('base sha16 %s' % hashlib.sha256(orig).hexdigest()[:16])
    for tag, base in (('R1', R1B), ('R2', R2B)):
        if struct.unpack_from('<I', orig, base + 0x0C)[0] != hdr_crc(orig[base:base + 96]):
            sys.exit('base CRC invalid in %s' % tag)
    print('base CRCs OK')

    docs = find_docs(orig)
    if len(docs) != 2 or docs[0][0] != DOC1 or docs[1][0] != DOC2:
        sys.exit('expected 2 NVRAM docs at 0x%x / 0x%x, found %s'
                 % (DOC1, DOC2, [hex(d[0]) for d in docs]))
    d1t, d2t = docs[0][1], docs[1][1]

    o = json.loads(d1t)
    dbv = find_db(o)
    if not dbv:
        sys.exit('db variable not found in NVRAM doc1')
    db_old = bytes(dbv['Data'])
    print('db: attrs=%s len=%d head=%s' % (dbv['Attributes'], len(db_old), db_old[:16].hex()))

    # walk the existing concatenated EFI_SIGNATURE_LISTs (validates the layout)
    off, lists = 0, []
    while off < len(db_old):
        if off + 28 > len(db_old):
            sys.exit('list header overruns at %d' % off)
        t = db_old[off:off + 16]
        ls = struct.unpack_from('<I', db_old, off + 16)[0]
        hs = struct.unpack_from('<I', db_old, off + 20)[0]
        ss = struct.unpack_from('<I', db_old, off + 24)[0]
        if t != X509_B:
            print('note: non-X509 list at %d (type %s) — left intact' % (off, t.hex()))
        if not (28 <= ls <= len(db_old) - off):
            sys.exit('bad ListSize %d at %d' % (ls, off))
        lists.append((off, ls, hs, ss))
        off += ls
    if off != len(db_old):
        sys.exit('lists cover %d != db len %d' % (off, len(db_old)))
    print('db lists (off,listsig,hdrlen,sigsize): %s' % lists)

    der = Path(a.cert).read_bytes()
    if not der or der[0] != 0x30:
        sys.exit('cert does not look like DER')
    print('cert len=%d sha256=%s' % (len(der), hashlib.sha256(der).hexdigest()[:16]))

    sig_size = 16 + len(der)      # EFI_SIGNATURE_DATA = Owner(16) + cert
    list_size = 28 + sig_size     # list header(28) + HeaderSize(0) + 1 signature
    new_list = (X509_B + struct.pack('<I', list_size) + struct.pack('<I', 0)
                + struct.pack('<I', sig_size) + owner + der)
    assert len(new_list) == list_size
    db_new = db_old + new_list
    print('db new len: %d' % len(db_new))

    def replace_db(text, tag):
        key = '"db":{"Attributes":%d,"Data":[' % dbv['Attributes']
        if text.count(key) != 1:
            sys.exit('db key not found exactly once in %s' % tag)
        at = text.find(key) + len(key)
        j = at
        while j < len(text) and text[j] != ']':
            j += 1
        if j >= len(text):
            sys.exit('db Data array not terminated in %s' % tag)
        new = text[:at] + ','.join(str(x) for x in db_new) + text[j:]
        o2 = json.loads(new)
        db2 = find_db(o2)
        if not db2 or bytes(db2['Data']) != db_new or db2['Attributes'] != dbv['Attributes']:
            sys.exit('db replacement verification failed in %s' % tag)
        print('%s db replaced ok (%d -> %d B)' % (tag, len(db_old), len(db_new)))
        return new

    n1 = replace_db(d1t, 'doc1')
    n2 = replace_db(d2t, 'doc2')
    new_len = len(n1.encode('utf-16-le'))
    if len(n2.encode('utf-16-le')) != new_len:
        sys.exit('doc sizes differ after edit')
    print('new doc size = %d (both)' % new_len)
    if DOC1 + new_len + 2 >= DOC2 or DOC2 + new_len + 2 >= 0x3FFDFD:
        sys.exit('new docs do not fit in the file')

    out = bytearray(orig)
    out[DOC1:DOC1 + new_len] = n1.encode('utf-16-le')
    out[DOC1 + new_len:DOC1 + new_len + 2] = b'\x00\x00'
    out[DOC2:DOC2 + new_len] = n2.encode('utf-16-le')
    out[DOC2 + new_len:DOC2 + new_len + 2] = b'\x00\x00'
    struct.pack_into('<I', out, R1B + 0x30, new_len + 2)
    struct.pack_into('<I', out, R1B + 0x50, new_len + 2)
    struct.pack_into('<I', out, R1B + 0x0C, hdr_crc(out[R1B:R1B + 96]))

    b = bytes(out)
    if struct.unpack_from('<I', b, R1B + 0x0C)[0] != hdr_crc(b[R1B:R1B + 96]):
        sys.exit('R1 CRC mismatch after build')
    if struct.unpack_from('<I', b, R2B + 0x0C)[0] != hdr_crc(orig[R2B:R2B + 96]):
        sys.exit('R2 CRC mismatch after build')
    r1s1 = struct.unpack_from('<I', b, R1B + 0x30)[0]
    r1s2 = struct.unpack_from('<I', b, R1B + 0x50)[0]
    print('R1 S=(%d,%d) CRC=0x%08X OK; R2 untouched'
          % (r1s1, r1s2, struct.unpack_from('<I', b, R1B + 0x0C)[0]))
    if r1s1 != r1s2 or r1s1 != new_len + 2:
        sys.exit('R1 S fields wrong')

    # byte-diff audit: ONLY the docs + R1 header bytes may change
    expect = (set(range(DOC1, DOC1 + new_len + 2)) | set(range(DOC2, DOC2 + new_len + 2))
              | set(range(R1B + 0x0C, R1B + 0x10)) | set(range(R1B + 0x30, R1B + 0x34))
              | set(range(R1B + 0x50, R1B + 0x54)))
    changed = [i for i in range(len(b)) if b[i] != orig[i]]
    outside = set(changed) - expect
    print('changed=%d unexpected=%d' % (len(changed), len(outside)))
    if outside:
        sys.exit('unexpected changed bytes: %s' % [hex(x) for x in sorted(outside)[:10]])

    dd = find_docs(b)
    if len(dd) != 2 or dd[0][0] != DOC1 or dd[1][0] != DOC2:
        sys.exit('docs not re-found after build')
    for (_s, t) in dd:
        if len(t.encode('utf-16-le')) != new_len:
            sys.exit('doc size mismatch after build')
    for g in GPT_OFFS:
        if b[g:g + 92] != orig[g:g + 92]:
            sys.exit('GPT region changed!')
    print('BUILD OK; sha16 %s' % hashlib.sha256(b).hexdigest()[:16])

    if a.write:
        live = Path(a.live)
        if live.exists():
            bak = live.with_name(live.name + '.bak-' + time.strftime('%Y%m%d-%H%M%S'))
            shutil.copy2(live, bak)
            print('backup of live file: %s' % bak)
        live.write_bytes(b)
        if live.read_bytes() != b:
            sys.exit('readback verification failed')
        print('WROTE %s; readback verified' % live)
    else:
        print('dry run. Re-run with --write to apply to the live file.')


if __name__ == '__main__':
    main()
