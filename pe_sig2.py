#!/usr/bin/env python3
"""pe_sig2.py — extract the Authenticode (PKCS#7) signature chain from a UEFI
PE image and identify the leaf signer certificate.

Use this BEFORE injecting any cert into db: the firmware only verifies the
image if the actual SIGNER (leaf) cert is present in db. A PKCS#7 may contain
more certs than the vendor ships in the ISO.

Location of the WIN_CERTIFICATE: PE DataDirectory[4] (Certificate). For
Authenticode images the directory value is a FILE OFFSET (the cert table is
appended after the last section), NOT an RVA — try it as a file offset first,
fall back to RVA->section mapping.
WIN_CERTIFICATE header: DWORD dwLength, WORD wRevision (0x0200 = rev 1.1),
WORD wCertificateType (2 = PKCS#7).

No dependencies (hand-rolled DER walker).

Usage:
  python pe_sig2.py <IMAGE.EFI> [--dump-dir DIR] [--ref CERT.DER ...]
"""
import argparse
import hashlib
import io
import struct
import sys
from pathlib import Path

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')


def tlv(b, off=0):
    if off >= len(b):
        raise ValueError('tlv: off past end')
    tag = b[off]
    off += 1
    if off >= len(b):
        raise ValueError('tlv: no length byte')
    ln = b[off]
    off += 1
    if ln & 0x80:
        n = ln & 0x7F
        if n == 0:
            raise ValueError('tlv: indefinite length')
        if off + n > len(b):
            raise ValueError('tlv: long-form length overruns')
        ln = int.from_bytes(b[off:off + n], 'big')
        off += n
    if off + ln > len(b):
        raise ValueError('tlv: body overruns')
    return tag, b[off:off + ln], off + ln


def walk(b):
    items = []
    off = 0
    while off < len(b):
        tag, body, off = tlv(b, off)
        items.append((tag, body))
    assert off == len(b)
    return items


def oid(b):
    if not b:
        return '?'
    p = [str(b[0] // 40), str(b[0] % 40)]
    v = 0
    for x in b[1:]:
        v = (v << 7) | (x & 0x7F)
        if not x & 0x80:
            p.append(str(v))
            v = 0
    return '.'.join(p)


def name(b):
    tag, body, _ = tlv(b, 0)
    assert tag == 0x30, 'NAME not a SEQUENCE'
    out = []
    off = 0
    while off < len(body):
        t, rdn, off = tlv(body, off)
        assert t == 0x31
        o2 = 0
        while o2 < len(rdn):
            t2, av, o2 = tlv(rdn, o2)
            assert t2 == 0x30
            i = 0
            t3, o, i = tlv(av, i)
            assert t3 == 0x06
            t4, v, i = tlv(av, i)
            out.append('%s=%s' % (oid(o), v.decode('utf-8', 'replace')))
    return out


def cert_info(der):
    tag, ci, _ = tlv(der, 0)
    assert tag == 0x30
    items = walk(ci)
    if len(items) < 3 or items[0][0] != 0x30 or items[1][0] != 0x30:
        return None
    tbs = items[0][1]
    titems = walk(tbs)
    i0 = 1 if titems[0][0] == 0xA0 else 0
    if i0 + 5 >= len(titems) or titems[i0][0] != 0x02:
        return None
    serial = int.from_bytes(titems[i0][1], 'big')
    issuer = titems[i0 + 2][1]
    validity = titems[i0 + 3][1]
    subject = titems[i0 + 4][1]
    spki = titems[i0 + 5][1]
    vitems = walk(validity)
    nb = vitems[0][1].decode('ascii', 'replace')
    na = vitems[1][1].decode('ascii', 'replace')
    sa = oid(walk(items[1][1])[0][1])
    bc = None
    for t, body in titems:
        if t == 0xA3:
            try:
                _t, exts, _ = tlv(body, 0)
                for _t2, ebody in walk(exts):
                    its = walk(ebody)
                    if oid(its[0][1]) == '2.5.29.19':
                        o = 1
                        crit = False
                        if o < len(ebody) and ebody[o] == 0x01:
                            crit = bool(ebody[o + 2])
                            o += ebody[o + 1] + 2
                        _t, oc, o = tlv(ebody, o)
                        _t, ocs, o = tlv(oc, 0)
                        bc = (crit, bool(ocs) and bool(ocs[-1] & 1))
                        break
            except Exception:
                pass
    spk = walk(spki)
    keysha = hashlib.sha256(spk[1][1][1:]).hexdigest()[:16] if len(spk) >= 2 else '??'
    return {'der': der, 'serial': serial, 'issuer': issuer, 'subject': subject,
            'not_before': nb, 'not_after': na, 'sigalg': sa, 'bc': bc, 'keysha': keysha}


def is_cert(b):
    """b = full TLV slice. True if it parses as a plausible X.509 certificate."""
    try:
        tag, ci, end = tlv(b, 0)
        if tag != 0x30 or end != len(b):
            return False
        items = walk(ci)
        if len(items) != 3:
            return False
        if items[0][0] != 0x30 or items[1][0] != 0x30 or items[2][0] != 0x03:
            return False
        titems = walk(items[0][1])
        i0 = 1 if titems[0][0] == 0xA0 else 0
        if i0 + 5 >= len(titems):
            return False
        if titems[i0][0] != 0x02:
            return False
        if titems[i0 + 1][0] != 0x30:
            return False
        for k in (2, 3, 4, 5):
            if titems[i0 + k][0] != 0x30:
                return False
        return True
    except Exception:
        return False


def pe_pkcs7(path):
    b = Path(path).read_bytes()
    pe = struct.unpack_from('<I', b, 0x3C)[0]
    if b[pe:pe + 4] != b'PE\0\0':
        raise ValueError('not a PE image')
    nsec = struct.unpack_from('<H', b, pe + 6)[0]
    opt_size = struct.unpack_from('<H', b, pe + 20)[0]
    opt = pe + 24
    magic = struct.unpack_from('<H', b, opt)[0]
    dd_off = opt + (108 if magic == 0x20B else 92)
    ndd = struct.unpack_from('<I', b, dd_off)[0]
    dd = dd_off + 4
    cert_val, cert_size = struct.unpack_from('<II', b, dd + 4 * 8)
    if not cert_val or not cert_size:
        raise ValueError('no certificate table')

    def try_off(off):
        if off + 8 > len(b):
            return None
        wlen, wrev, wctype = struct.unpack_from('<IHH', b, off)
        if wrev not in (1, 0x0200) or wctype != 0x0002 or not (16 <= wlen <= 0x10000):
            return None
        if off + wlen > len(b) + 1:
            return None
        return off, wlen

    off = None
    r = try_off(cert_val)  # Authenticode: directory value == file offset
    if r:
        off, wlen = r
    else:
        secc = opt + opt_size
        for i in range(nsec):
            s = secc + i * 40
            va, rs, pr = struct.unpack_from('<III', b, s + 12)
            if va <= cert_val < va + max(rs, 1):
                r = try_off(cert_val - va + pr)
                if r:
                    off, wlen = r
                break
    if off is None:
        raise ValueError('cannot locate WIN_CERTIFICATE (dir value 0x%x)' % cert_val)
    return b[off + 8:off + wlen]


def pkcs7(pk):
    tag, ci, _ = tlv(pk, 0)
    assert tag == 0x30
    items = walk(ci)
    assert items[0][0] == 0x06
    da_oid = oid(items[0][1])
    assert da_oid == '1.2.840.113549.1.7.2', 'not signedData (%s)' % da_oid
    assert items[1][0] == 0xA0
    t2, sd, _ = tlv(items[1][1], 0)
    assert t2 == 0x30
    sitems = walk(sd)
    assert sitems[0][0] == 0x02 and sitems[1][0] == 0x31
    certs = []
    for idx in range(2, len(sitems)):
        t, body = sitems[idx]
        if t != 0xA0:
            continue
        try:
            ftag, fbody, foff = tlv(body, 0)
        except Exception:
            continue
        if ftag != 0x30 or not is_cert(body[:foff]):
            continue  # not the cert list (this is the content)
        off = 0
        while off < len(body):
            ctag, cbody, off = tlv(body, off)
            assert ctag == 0x30
            certs.append(cbody)
    si_set = sitems[-1]
    assert si_set[0] == 0x31
    signers = []
    for t, body in walk(si_set[1]):
        assert t == 0x30
        its = walk(body)
        assert its[0][0] == 0x02 and its[1][0] == 0x30
        sid_items = walk(its[1][1])
        assert len(sid_items) == 2 and sid_items[1][0] == 0x02
        signers.append({'issuer': sid_items[0][1],
                        'serial': int.from_bytes(sid_items[1][1], 'big')})
    return certs, signers


def main():
    ap = argparse.ArgumentParser(description='Extract the Authenticode chain from a UEFI PE image.')
    ap.add_argument('image', help='UEFI PE image (e.g. BOOTX64.EFI, a UKI)')
    ap.add_argument('--dump-dir', default=None, help='write each cert to <dir>/<stem>_certN.der')
    ap.add_argument('--ref', nargs='*', default=[], help='reference cert DER files to compare against')
    a = ap.parse_args()

    pk = pe_pkcs7(a.image)
    print('== %s : PKCS#7 %d B' % (a.image, len(pk)))
    certs, signers = pkcs7(pk)
    print('certs in set: %d, signers: %d' % (len(certs), len(signers)))

    refs = {str(Path(p)): Path(p).read_bytes() for p in a.ref}

    infos = []
    for i, c in enumerate(certs):
        info = cert_info(c)
        infos.append(info)
        if info is None:
            print('cert[%d] len=%d sha16=%s  (not parseable as X.509)'
                  % (i, len(c), hashlib.sha256(c).hexdigest()[:16]))
            continue
        m = [k for k, v in refs.items() if v == c]
        print('cert[%d] len=%d sha16=%s serial=0x%x keysha=%s%s'
              % (i, len(c), hashlib.sha256(c).hexdigest()[:16], info['serial'],
                 info['keysha'], '   MATCHES-REF: ' + ', '.join(m) if m else ''))
        print('   subject: %s' % ', '.join(name(info['subject'])))
        print('   issuer : %s' % ', '.join(name(info['issuer'])))
        print('   valid  : %s .. %s    sigalg=%s    BC(crit,CA)=%s'
              % (info['not_before'], info['not_after'], info['sigalg'], info['bc']))
        if a.dump_dir:
            d = Path(a.dump_dir)
            d.mkdir(parents=True, exist_ok=True)
            (d / (Path(a.image).stem + '_cert%d.der' % i)).write_bytes(c)
    print('   (certs dumped to %s)' % a.dump_dir if a.dump_dir and certs else '')

    leaf_idx = None
    for s in signers:
        print('signer: serial=0x%x  issuer=%s' % (s['serial'], ', '.join(name(s['issuer']))))
        for i, info in enumerate(infos):
            if info and info['serial'] == s['serial'] and info['issuer'] == s['issuer']:
                leaf_idx = i
                print('  >>> LEAF = cert[%d]' % i)
                break
        else:
            print('  >>> LEAF NOT IN CERT SET (signer cert missing from PKCS#7)')

    if leaf_idx is not None:
        c = certs[leaf_idx]
        m = [k for k, v in refs.items() if v == c]
        print('LEAF sha256=%s len=%d' % (hashlib.sha256(c).hexdigest()[:16], len(c)))
        print('LEAF matches refs: %s' % (m if m else 'NONE'))
        print('-> the cert to put in db is the LEAF (dump it with --dump-dir).')


if __name__ == '__main__':
    main()
