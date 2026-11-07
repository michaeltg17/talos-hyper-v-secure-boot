#!/usr/bin/env python3
"""talosconfig_build.py — build a working talosconfig for an INSTALLED Talos node.

After `talosctl apply-config` the node's machine API requires mTLS and
`--insecure` stops working (it is maintenance-mode only; symptom:
`tls: certificate required`). The client certificate a talosconfig needs is
issued by the **machine CA of the config you applied**, so:

  extract  pull machine.ca (crt + key, PEM) out of the applied config file
  build    base64 the CA + client cert/key into a talosconfig context

The middle step — turning the CA into a client cert — is done by talosctl
itself (Ed25519 key -> CSR with role os:admin -> cert signed by the CA):

    talosctl gen key --name client
    talosctl gen csr --key client.key --roles os:admin --ip <node-ip>
    talosctl gen crt --ca ca --csr client.csr --name client --hours 8760

`gen crt --ca` takes a BASENAME: it reads ./ca.crt and ./ca.key from the
current directory (that is why `extract` writes exactly those names).

Usage:
  python talosconfig_build.py extract <applied-config.yaml> <workdir>
  python talosconfig_build.py build   <workdir> <node-ip> [context-name]
      # build needs <workdir>/{ca.crt, client.crt, client.key}
      # writes <workdir>/talosconfig.yaml
"""
import base64
import re
import sys
from pathlib import Path


def find_ca(lines, indent):
    """Find a 'ca:' key with exactly `indent` leading spaces; return (crt_b64, key_b64)."""
    for i, line in enumerate(lines):
        stripped = line.lstrip(' ')
        if len(line) - len(stripped) != indent:
            continue
        if not re.match(r'^ca:\s*(#.*)?$', stripped):
            continue
        crt = key = None
        for line2 in lines[i + 1:min(i + 6, len(lines))]:
            if not line2.strip() or line2.lstrip().startswith('#'):
                continue
            mc = re.match(r'^\s+crt:\s*(\S+)', line2)
            if mc:
                crt = mc.group(1)
            mk = re.match(r'^\s+key:\s*(\S+)', line2)
            if mk:
                key = mk.group(1)
        if crt and key:
            return crt, key
    return None, None


def cmd_extract(cfg_path: Path, workdir: Path) -> None:
    lines = cfg_path.read_text(encoding='utf-8').splitlines()
    # machine.ca is 4-space indented in a gen-config output; deeper 'ca:' keys
    # (e.g. cluster.etcd.ca at 8) belong to the k8s PKI, not the machine API.
    crt_b64, key_b64 = find_ca(lines, 4)
    if not crt_b64 or not key_b64:
        sys.exit('machine.ca (crt+key) not found in %s' % cfg_path)
    crt = base64.b64decode(crt_b64).decode('utf-8')
    key = base64.b64decode(key_b64).decode('utf-8')
    if '-----BEGIN' not in crt or '-----BEGIN' not in key:
        sys.exit('decoded machine.ca values do not look like PEM')
    workdir.mkdir(parents=True, exist_ok=True)
    (workdir / 'ca.crt').write_text(crt, encoding='utf-8')
    (workdir / 'ca.key').write_text(key, encoding='utf-8')
    print('wrote %s and %s' % (workdir / 'ca.crt', workdir / 'ca.key'))


def cmd_build(workdir: Path, node_ip: str, name: str) -> None:
    def b64(fname):
        p = workdir / fname
        if not p.exists():
            sys.exit('%s missing — run the talosctl gen key/csr/crt steps first' % p)
        return base64.b64encode(p.read_text(encoding='utf-8').encode('utf-8')).decode('ascii')

    doc = (
        'context: %s\n'
        'contexts:\n'
        '  %s:\n'
        '    endpoints:\n'
        '      - %s\n'
        '    nodes:\n'
        '      - %s\n'
        '    ca: %s\n'
        '    crt: %s\n'
        '    key: %s\n'
        % (name, name, node_ip, node_ip, b64('ca.crt'), b64('client.crt'), b64('client.key'))
    )
    out = workdir / 'talosconfig.yaml'
    out.write_text(doc, encoding='utf-8')
    print('wrote %s' % out)


def main() -> None:
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    stage = sys.argv[1]
    if stage == 'extract' and len(sys.argv) == 4:
        cmd_extract(Path(sys.argv[2]), Path(sys.argv[3]))
    elif stage == 'build' and 4 <= len(sys.argv) <= 5:
        name = sys.argv[4] if len(sys.argv) == 5 else 'talos'
        cmd_build(Path(sys.argv[2]), sys.argv[3], name)
    else:
        sys.exit(__doc__)


if __name__ == '__main__':
    main()
