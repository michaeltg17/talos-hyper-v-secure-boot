# Talos Linux + UEFI Secure Boot on Hyper-V (Gen 2)

Install [Talos Linux](https://talos.dev) from the official **secureboot** ISO on a
Windows Hyper-V **Gen 2** VM that boots with **UEFI Secure Boot enabled**
(template `MicrosoftUEFICertificateAuthority`) — and end with the *installed*
system still verifying its signed boot chain against the firmware.

Verified end-to-end on Talos **v1.14.5**: after the runbook, the installer TUI
reports `SECUREBOOT ✓ True`, and the installed node keeps booting with Secure
Boot ON (the installed UKI is signed by the same certificate we add to the
firmware `db` — no further work needed).

No MOK, no third-party firmware, no signed shim chain: a byte-level edit of the
VM's NVRAM store.

> **Generic variant:** the same mechanism, vendor-neutral (any key, any OS,
> `db` and `dbx`), is packaged as a standalone toolkit in
> [michaeltg17/hyper-v-secure-boot-custom-keys](https://github.com/michaeltg17/hyper-v-secure-boot-custom-keys) —
> this repo remains the Talos-specific, proven runbook.

## Why this is hard (root cause)

With `MicrosoftUEFICertificateAuthority`, the Hyper-V UEFI firmware verifies
every boot image (shim, then UKI) against the UEFI NVRAM variable **`db`**,
which ships with **Microsoft's certificates only**. The Talos secureboot ISO is
signed by Sidero's certificate, which is not in `db`, so the firmware rejects
the boot with *"The signed image's hash is not …"* and the VM boot-loops.

**The fix:** append Sidero's signing certificate to `db` **inside the VM's
`.vmgs` file** (Hyper-V's on-disk firmware NVRAM), restart the `vmms` service
(it caches NVRAM in memory), then boot. The firmware accepts an extended `db`.

## Repo layout

| File | Purpose |
| --- | --- |
| `vmgs_dbinject.py` | **The core step.** Rebuilds a `.vmgs` with a cert appended to `db` (both NVRAM docs, valid CRCs, byte-diff audit). Dry-run by default, `--write` to apply. |
| `db_decode.py` | Decode/audit the `db` variable of any `.vmgs`: walks the `EFI_SIGNATURE_LIST`s, prints each cert's fingerprint, `--ref` to byte-compare against reference certs. |
| `pe_sig2.py` | Extract the Authenticode (PKCS#7) chain from a UEFI PE image and identify the **leaf signer** — always run this *before* injecting anything into `db`. |
| `talosconfig_build.py` | Post-install mTLS: extract the machine CA from the applied config, and build the `talosconfig` once `talosctl gen key/csr/crt` has issued the client cert. |
| `talos-config.yaml` | Template for the Talos v1.14 machine-config documents you control (install, static IP, DNS, endpoint). |
| `ps/start_vm.ps1` | Boot with a `.vmgs` sha256 audit (detects firmware rewrites). |
| `ps/stop_vm.ps1` | Force-stop and wait for the `.vmgs` lock to release. |
| `ps/restart_vmms.ps1` | `Restart-Service vmms` (flushes the NVRAM cache) with an integrity check. |
| `ps/monitor_boot.ps1` | Poll VM state + DHCP IP while the installer boots. |
| `ps/vm_console_shot.ps1` | Screenshot the vmconnect console (read the installer TUI when the IP is unknown). |

Python: stdlib only, 3.8+. PowerShell: Windows PowerShell 5.1+, Hyper-V module.
The `.ps1` helpers take `-VMName` and locate the `.vmgs` themselves
(`<VM folder>\<VM id>.vmgs`).

> **Antivirus note:** Windows Defender heuristics can flag
> `ps/vm_console_shot.ps1` (screen-capture + P/Invoke is a pattern shared with
> keyloggers). It is a false positive — the script only opens the local
> `vmconnect` window, measures it, and saves one PNG. If your AV quarantines
> it, review the content and add an exclusion for the repo folder.

## Verified format facts (these cost hours — do not re-derive)

### The signature chain (Talos secureboot ISO, v1.14.5)

| Fact | Value |
| --- | --- |
| Leaf signer (self-signed) | `C=US, O=Sidero Labs Inc., OU=Sidero Labs SecureBoot, CN=talos.dev` |
| Validity | 2023-11-21 → 2033-11-18 |
| Signature algorithm | `sha256WithRSAEncryption` |
| Cert DER | ISO file `EFI\KEYS\UKI_SIGNING_CERT.DER` (1439 B) |
| Same PKCS#7 (1 cert, 1 signer) | embedded in **both** `EFI\BOOT\BOOTX64.EFI` and the UKI `EFI\LINUX\TALOS_*.EFI` |

So the **one** cert that must go into `db` is `UKI_SIGNING_CERT.DER`. Verify
the actual signer with `pe_sig2.py` (or `openssl pkcs7 -inform DER -print_certs`
in WSL) before injecting: a PKCS#7 can carry more certs than the vendor ships,
and the firmware needs the **leaf** signer.

### `db` variable byte format (decoded from the firmware's own MS entries)

`db` = concatenation of `EFI_SIGNATURE_LIST`s. Per list:

```
X509_GUID(16) | ListSize(u32le) | HeaderSize(u32le) | SigSize(u32le) | [ Owner(16) + cert DER ] × n
```

- `X509_GUID` is stored in this NVRAM in **hex-string byte order**:
  `a159c0a5e494a74a87b5ab155c2bf072` (not EFI little-endian field order).
- `SigSize = 16 + cert_len` — signature data is `Owner(16) + cert`, **no extra
  GUID inside**. Writing `32 + cert_len` with the GUID included is the classic
  bug (firmware reads the cert as 16 zero bytes + cert → "no match").
- `ListSize = 28 + HeaderSize + n·SigSize`.
- `Owner` may be all zeros (firmware accepts it; Microsoft's own entries use a
  non-zero owner).
- `db` has `Attributes = 39` (NV|BS|RT|LOCKED) — keep it.

### `.vmgs` file format (VMGS v1, 4 MiB = `0x400200`)

| What | Where / rule |
| --- | --- |
| GPT | `0x200` and `0x3FFE00` — never touch |
| NVRAM docs | **two redundant** UTF-16LE JSON docs at fixed offsets `0x4800` (doc1) and `0x200200` (doc2), each followed by exactly one NUL (2 bytes) |
| Doc discovery | byte string `{"Version":{"Major":0,"Minor":0},"Devices"` as UTF-16LE |
| Doc shape | `{ "Version":…, "Devices":{ …, "ac6b8dc1-3257-4a70-b1b2-a9c9215659ad" (Virtual BIOS): …, "States":{ "Nvram":{ "Vendors":{ "<guid>":{ "Variables":{ "db":{ "Attributes":39, "Data":[ints] } } } } } } }` |
| `Data` array | byte values as a JSON array of ints |
| GUESTRTS headers | two redundant 96-byte headers: **R1 @ `0x4400`** (current bank), **R2 @ `0x4600`** |
| S fields | `R1+0x30` = len(doc1)+2, `R1+0x50` = len(doc2)+2 — **per-doc, may legitimately differ**: the firmware itself stores different values (v1.14.5 run BASE: `247410` vs `246938` — doc1 carried a firmware-created `Boot0003` that doc2 lacked) |
| CRC | `header[0x0C] = zlib.crc32(header96 with bytes 12..16 zeroed)`. **Both** banks must validate. After an edit: update R1's S fields + R1 CRC; leave R2 untouched (its base CRC stays valid; a stale R2 S1 is tolerated — BASE ships `R2 S1=246460` while doc1 is 247410 long, and it powers on fine) |
| Space | new docs must fit: `0x200200 + new_len + 2 < 0x3FFDFD` |

### VMMS / firmware behavior (operational rules)

1. **VMMS caches NVRAM in memory.** A file-level `.vmgs` edit only reaches the
   firmware after `Restart-Service vmms`. No VMMS NVRAM-writing cmdlet between
   the edit and the boot. In the v1.14.5 run the edit was applied with the VM
   **Off** and took effect on the next boot **without** a VMMS restart — keep
   the restart as the conservative default when other VMs are running or the
   VMMS state is uncertain.
2. **Every `Stop-VM` and every failed boot makes the firmware rewrite
   `.vmgs`**, clobbering file-level edits. Keep an immutable **BASE** backup
   (a known-good, power-on-capable `.vmgs`) and **rebuild every attempt from
   BASE** — never patch the live file across reboots.
3. MOK vendor variables (`MokList` etc. under the shim vendor GUID) are
   **rejected** by this firmware (`Virtual BIOS Failed to resume 0x80070570`).
   Don't go down the MOK path — `db` works.
4. An extended `db` (a third concatenated list) is **accepted**.

## Runbook

Example values below (replace with your own): LAN `192.168.1.0/24`, gateway
`192.168.1.1`, desired node IP `192.168.1.50`, VM name `Talos`, install disk
`<install.vhdx>`.

### Step 0 — Prerequisites

- Windows host with the Hyper-V role + Python 3 (stdlib only).
- The Talos **secureboot** ISO. For v1.14.5 the schematic hash is
  `376567988ad370138ad8b2698212367b8edcb69b5fd68c80be1f2ec7d603b4ba`, i.e.
  `https://factory.talos.dev/image/<hash>/v1.14.5/metal-amd64-secureboot.iso`.
  This hash reappears in step 6 as part of the installer image reference.
- `talosctl` for the **same** version:
  `https://github.com/siderolabs/talos/releases/download/v1.14.5/talosctl-windows-amd64.exe`
  (asset name is `talosctl-windows-amd64.exe`; `curl.exe -sSL` is the most
  reliable downloader for GitHub release URLs).
- Extract the ISO once (any tool) — you need `EFI\KEYS\UKI_SIGNING_CERT.DER`.

### Step 1 — VM setup + get a power-on-capable BASE `.vmgs`

```powershell
New-VM -Name Talos -Generation 2 -MemoryStartupBytes 2GB -Path '<VM folder>'
Set-VMFirmware -VMName Talos -EnableSecureBoot On    # template = MicrosoftUEFICertificateAuthority
Add-VMDvdDrive -VMName Talos
Add-VHD -VMName Talos -Path '<install.vhdx>' -ControllerNumber 0
Set-VMDvdDrive -VMName Talos -Path '<metal-amd64-secureboot.iso>'
Start-VM Talos    # firmware runs, writes a clean .vmgs (image verification fails - expected)
.\ps\stop_vm.ps1 -VMName Talos    # waits for the .vmgs lock to release
Copy-Item '<VM folder>\<guid>.vmgs' '<VM folder>\<guid>.vmgs.BASE'
```

BASE must be a file that **powers on** (the firmware runs). Verify by starting
once more with BASE in place — it may still fail *image* verification, that's
fine. The `.vmgs` lives next to the VM's `.vhx`:
`<VM folder>\<(Get-VM Talos).VMId>.vmgs`.

### Step 2 — Confirm the real signer (before injecting anything)

```powershell
python pe_sig2.py '<iso-extract>\EFI\BOOT\BOOTX64.EFI' `
    --dump-dir . --ref '<iso-extract>\EFI\KEYS\UKI_SIGNING_CERT.DER'
```

Check that the **LEAF** signer (matched by serial + issuer) is the cert you are
about to inject — subject, validity, sha256. Repeat on the UKI
(`EFI\LINUX\TALOS_*.EFI`) to be thorough.

### Step 3 — Build the db-injected `.vmgs` (the core step)

```powershell
python vmgs_dbinject.py --base '<VM folder>\<guid>.vmgs.BASE' `
    --live '<VM folder>\<guid>.vmgs' `
    --cert '<iso-extract>\EFI\KEYS\UKI_SIGNING_CERT.DER'
# prints "BUILD OK" with 0 unexpected bytes -> then:
python vmgs_dbinject.py --base '<VM folder>\<guid>.vmgs.BASE' `
    --live '<VM folder>\<guid>.vmgs' `
    --cert '<iso-extract>\EFI\KEYS\UKI_SIGNING_CERT.DER' --write
```

The builder is a dry-run by default: it verifies the base CRCs, walks the
existing `db` lists, rebuilds **both** NVRAM docs, updates R1's S fields + CRC,
and byte-diffs the result (only the docs + R1 header bytes may change).
`--write` backs up the live file, writes, and readback-verifies.

Audit any `.vmgs` with `db_decode.py` — it prints each `EFI_SIGNATURE_LIST`
and every cert's fingerprint, and flags `--ref` matches.

### Step 4 — Flush the VMMS cache + boot

```powershell
.\ps\restart_vmms.ps1 -VMName Talos   # all VMs Off; verifies .vmgs unchanged by the restart
.\ps\start_vm.ps1   -VMName Talos     # boots; prints state + pre/post .vmgs hashes
```

Expected: the firmware accepts the extended `db`, the Sidero-signed shim
loads, the UKI loads, and the **Talos installer TUI** appears:

```
Talos (v1.14.5)
STAGE       Maintenance
READY       ✓ True
SECUREBOOT  ✓ True        <- runtime proof: Secure Boot ON, boot chain verified
```

### Step 5 — Get the installer's IP

- `Get-VMNetworkAdapter`'s `IPAddresses` is often **empty** on bridged
  (External switch) NICs even when the guest has an IP — don't trust it as
  the only source.
- The installer requests DHCP within ~1 minute of the TUI appearing.
  `.\ps\monitor_boot.ps1 -VMName Talos` polls state + IP and pings once one
  shows up.
- Otherwise read the TUI header (it shows the IP):
  `.\ps\vm_console_shot.ps1 -VMName Talos` screenshots the console — or
  ping-scan your LAN.

### Step 6 — Apply the machine config (this triggers the install)

Talos **v1.14** machine configs are **multi-document** YAMLs: a
`v1alpha1.Config` document (PKI, token) plus per-domain resource documents
(`UnattendedInstallConfig`, `LinkConfig`, `ResolverConfig`,
`KubeClusterConfig`, …). The old `machine.network` / `machine.install` /
`machine.vip` fields were **moved out of v1alpha1** — don't hand-write them
and don't fight `--config-patch` with them.

```powershell
# 1) generate the full config set (PKI, tokens, cluster identity, UnattendedInstallConfig)
talosctl.exe gen config mycluster https://192.168.1.50:6443 `
    --install-image factory.talos.dev/metal-installer-secureboot/<IMAGE-HASH>:v1.14.5 `
    --install-disk /dev/sda `
    -t controlplane -o talos-controlplane.yaml --force

# 2) append the documents you control (templates in talos-config.yaml):
#    LinkConfig (static IP + default route), ResolverConfig (DNS)

# 3) apply to the installer (unauthenticated maintenance service - no talosconfig needed)
talosctl.exe apply-config --insecure --nodes <installer-ip> -f talos-controlplane.yaml
```

Notes:
- **Keep the applied config file** (e.g. `cp.yaml`) — step 8 extracts the
  machine CA from it to build the post-install talosconfig.
- `gen config` requires a **scheme+port** on the endpoint
  (`https://IP:6443`); a bare IP fails with "no scheme and port".
- Use **`--nodes`**, not `--endpoints` (with `--endpoints` alone it fails:
  "nodes are not set for the command").
- `installer.image` must be the **secureboot** installer image whose hash
  matches the ISO you booted — otherwise the installed boot chain is not the
  one the firmware verified.
- `LinkConfig.name` must be the **real** link name inside the guest. Talos
  1.14 uses the kernel's MAC-derived names (e.g. `enx00155d01640c` for MAC
  `00:15:5d:01:64:0c`) — get it from
  `talosctl get links --insecure --nodes <ip>`. A wrong name just means the
  node keeps its DHCP IP — fix and re-apply (apply-config is repeatable).
- The installer pulls the installer image from a registry, so the node needs
  a working gateway + DNS (check the host's default route; Talos' built-in
  DNS default is 1.1.1.1 + 8.8.8.8).
- Applying a static-IP config reconfigures the interface **immediately** —
  the RPC to the old DHCP IP may drop mid-response. That's fine; the config
  is persisted and the install continues.

### Step 7 — Eject the DVD (before the install reboot)

If the DVD is first in the boot order, a still-attached ISO makes the VM boot
the installer again after the install reboot:

```powershell
Set-VMDvdDrive -VMName Talos -Path $null
```

### Step 8 — Verify the installed system (mTLS — `--insecure` is gone)

Install takes ~2–5 min (image pull + write + reboot). The **first boot of the
installed system is then slow**: the kernel is up ~1 min after power-on (the
dmesg timestamps show it), but the machine API + node network can take
**~10+ min** (image pulls) — ~11 min in the v1.14.5 run on 2 GB / 1 vCPU;
giving the VM more RAM/CPU shortens the window. The console stays **black**
on a running installed node — there is no TUI — and VM CPU 0% is normal in
that window. Don't diagnose a "dead" node from the console before ~15 min;
poll the new static IP (192.168.1.50 in the example) instead.

**After `apply-config`, `--insecure` no longer works** — the maintenance
service is off and the machine API demands mTLS (symptom:
`tls: certificate required`). The client cert for a talosconfig is issued by
the **machine CA of the config you applied**:

```powershell
$gen = "$env:TEMP\talos-gen"; $tc = "$env:TEMP\talos-tc"
New-Item -ItemType Directory -Force $tc | Out-Null

# 1) machine CA (ca.crt + ca.key) out of the config you applied in step 6
python talosconfig_build.py extract "$gen\cp.yaml" $tc

# 2) client key -> CSR (role os:admin) -> cert signed by that machine CA
Set-Location $tc
talosctl.exe gen key --name client
talosctl.exe gen csr --key client.key --roles os:admin --ip 192.168.1.50
talosctl.exe gen crt --ca ca --csr client.csr --name client --hours 8760
# NOTE: --ca is a BASENAME: gen crt reads .\ca.crt and .\ca.key from the cwd

# 3) talosconfig (context with endpoints, nodes, base64 ca/crt/key)
python talosconfig_build.py build $tc 192.168.1.50 talos
```

Then verify and bootstrap — **bootstrap first**: a single control-plane node
stays in `STAGE=booting` (etcd pre-stage waiting) until `talosctl bootstrap`
runs, and `talosctl health` (default wait 20 min) blocks on etcd in the
meantime:

```powershell
# 1) confirm the node is reachable over mTLS
talosctl.exe version --talosconfig $tc\talosconfig.yaml   # Server: v1.14.5

# 2) bootstrap the single-node control plane (exit 0); STAGE=running READY=true
#    follows ~2 min later (watch with: talosctl get machinestatus)
talosctl.exe bootstrap --talosconfig $tc\talosconfig.yaml

# 3) health once the node is up
talosctl.exe health --talosconfig $tc\talosconfig.yaml --wait-timeout 120s   # all checks OK, exit 0

# 4) pull the admin kubeconfig, then verify with kubectl
talosctl.exe kubeconfig "$tc\kubeconfig.yaml" -f --merge=false --talosconfig $tc\talosconfig.yaml
kubectl get nodes --kubeconfig "$tc\kubeconfig.yaml"   # Ready, control-plane
```

**kubeconfig merge note:** `talosctl kubeconfig` with no path **merges into
`~/.kube/config`** by default (adds a `mycluster` context alongside any
existing clusters). For a standalone file use `-f --merge=false <path>`
(`-f` overwrites an existing file).

**Waiting state (normal, not a fault):** while the node awaits bootstrap,
`talosctl health --wait-timeout 5s` reports the etcd pre-stage failing every
~15 s:

```
service "etcd" ... current state [Failed] Failed to run pre stage:
failed to build initial etcd cluster: failed to build cluster arguments: timeout
```

That loop *is* the waiting state (cf. siderolabs/talos#10806): the pre-stage
retries until `talosctl bootstrap` is issued. Use it, together with
`talosctl logs machined --tail N | Select-String 'controller failed|etcd'`,
to distinguish "waiting" from a real failure. Related symptoms while etcd
isn't up yet: `talosctl logs etcd` fails with `log "etcd" was not registered`
(the container hasn't started), and kubelet logs show
`Authorization error (user=apiserver-kubelet-client …)` — a downstream
symptom of the API server not being up, not an RBAC bug.

Runtime proof that Secure Boot survived the install — from the *installed*
kernel (also shows the db the kernel parses for module signing):

```powershell
talosctl.exe dmesg --talosconfig $tc\talosconfig.yaml --nodes 192.168.1.50 2>&1 |
    Select-String 'Secure boot|locked down|UEFI:db'
# Secure boot enabled
# Kernel is locked down from EFI Secure Boot mode; see man kernel_lockdown.7
# integrity: Loading X.509 certificate: UEFI:db
```

The installed UKI on the VHDX is Sidero-signed (from the secureboot installer
image) and verifies against the **same** `db` entry, which the firmware
persists in NVRAM across reboots — the final system boots with Secure Boot
ON with no further work.

### Step 9 — Post-install: put the disk first in the boot order

A fresh Gen 2 VM's firmware boot list contains a **network (PXE) entry** that
can sit **ahead of the disk**. With that order, every power-on first tries
network boot and waits out the PXE timeout before falling through to the disk
— a noticeable delay on **every** boot. (It also matters if your LAN ever
serves PXE/HTTP images.)

Once the install is verified (step 8), make the disk the first entry:

- **Hyper-V Manager:** VM → *Firmware* → *Boot Entries* → move the
  **"EFI SCSI Device"** entry to the top.
- **PowerShell** — verified pattern. The `BootOrder` parameter takes
  `VMComponentObject[]` (the `VMBootSource` objects from `Get-VMFirmware`);
  bare strings like `Drive, Network` **do not bind**:

  ```powershell
  $fw    = Get-VMFirmware -VMName Talos
  $drive = @($fw.BootOrder | Where-Object { $_.BootType -eq 'Drive' })[0]
  $rest  = @($fw.BootOrder | Where-Object { $_ -ne $drive })
  Set-VMFirmware -VMName Talos -BootOrder (@($drive) + $rest)

  (Get-VMFirmware -VMName Talos).BootOrder |
      ForEach-Object { "{0} - {1}" -f $_.BootType, $_.Description }
  # Drive   - EFI SCSI Device
  # Network - EFI Network
  ```

  `VMBootSourceType` values: `Drive`, `Network`, `File` (plus `Unknown`).
  The change takes effect at the **next** boot; the VM may stay running
  while you apply it.

Post-install cleanup, while you're at it:

- Remove the now-empty DVD drive entirely — `Remove-VMDvdDrive -VMName Talos`
  (step 7 only *ejects* it, in time for the install reboot).
- If the first-boot window (step 8) was too long, give the VM more RAM/CPU —
  the ~11 min on 2 GB / 1 vCPU is image-pull time, not a boot-chain problem.

## Talos v1.14 machine-config quick reference

| Setting (old ≤1.13 location) | v1.14 document / field |
| --- | --- |
| install image + disk (`machine.install`) | `UnattendedInstallConfig` → `installer.image`, `provisioning.diskSelector.match` (CEL, e.g. `disk.dev_path == "/dev/sda"`), `provisioning.wipe` |
| static IP (`machine.network.interfaces[].ip`) | `LinkConfig` (named by interface) → `addresses[].address` (`IP/prefix`) |
| gateway (`machine.network.network`) | `LinkConfig` → `routes[]` (default route = `gateway` only; omit `destination` — `0.0.0.0/0` is rejected by the validator) |
| DNS (`machine.network.dns`) | `ResolverConfig` → `nameservers[].address` (built-in default is already 1.1.1.1 + 8.8.8.8) |
| hostname | `HostnameConfig` → `hostname` or `auto: stable` |
| cluster VIP (`machine.vip`) | `KubeClusterConfig` → `endpoint: https://<ip>:6443` |
| NTP (`machine.timeNtpServers`) | `TimeSyncConfig` |

A ready-to-edit template for the install/network/endpoint documents is
[`talos-config.yaml`](talos-config.yaml).

## Error map

| Symptom | Cause | Fix |
| --- | --- | --- |
| GRST `Failed to Power on 0x80070570` | both GUESTRTS banks' CRCs stale/invalid | recompute CRCs; rebuild from BASE |
| `Virtual BIOS Failed to resume 0x80070570` | MOK vendor variable present in NVRAM | remove the MOK vars; use `db` (proven) |
| Boots, but `The signed image's hash is not …` on every device | leaf signer cert not (correctly) in `db` | check list format (`Owner+cert`, `SigSize = 16 + cert`); confirm the actual **leaf** with `pe_sig2.py` |
| `0x800704D5` | transient VMMS lock | retry |
| `0x80070020` | VHD in use | wait / `Dismount-DiskImage` |
| edits vanish after a reboot/stop | firmware rewrote `.vmgs` | rebuild from BASE before every boot |
| VMMS ignores your edit | in-memory cache | `Restart-Service vmms` after every file edit |
| talosctl `nodes are not set` | used `--endpoints` without `--nodes` | `apply-config --insecure --nodes <ip> -f <cfg>` |
| talosctl `no scheme and port` | endpoint missing scheme+port | `https://<ip>:6443` |
| `tls: certificate required` after apply-config | `--insecure` is maintenance-mode only; machine API now needs mTLS | build a talosconfig from the applied config's machine CA (step 8) |
| `resource type "ms" is ambiguous` (v1.14) | alias collides (machinestatus/manifeststatus/memorystats/mountstatuses) | use the full resource name: `talosctl get machinestatus` |
| `unknown command "status"` / `"read-file"` (v1.14) | commands renamed vs ≤1.13 | `talosctl get machinestatus`, `talosctl health`, `talosctl read <path>` |
| talosctl `unknown keys found during decoding` (e.g. `machine.network.dns`) | v1.14 moved those fields out of `v1alpha1` | use the resource documents instead (see the table above) |
| `"Config" "v1alpha1": not registered` | config file starts with `apiVersion:`/`kind: Config` | v1.14 files start with `version: v1alpha1`; generate with `talosctl gen config` |
| `failed to build initial etcd cluster: failed to build cluster arguments: timeout` looping every ~15 s | single control-plane node **awaiting `talosctl bootstrap`** — the waiting state, not a fault | run `talosctl bootstrap`; node reaches `running/true` in ~2 min |
| `log "etcd" was not registered` (`talosctl logs etcd`) | etcd container hasn't started (pre-stage waiting/stuck) | surface the pre-stage state with `talosctl health --wait-timeout 5s`; bootstrap |
| kubelet `Authorization error (user=apiserver-kubelet-client …)` | API server not fully up yet (downstream symptom) | wait for bootstrap to finish; not an RBAC bug |
| Black console + VM CPU 0% after the install reboot | slow first boot of the installed node (kernel ~1 min, machine API/network ~10+ min; no TUI on an installed node) | wait up to ~15 min; check `talosctl dmesg` timestamps and ping the static IP |
| GitHub release download resets/401 | artifact/auth quirks | `curl.exe -sSL`; list exact asset names via the API |
| Defender quarantines `ps/vm_console_shot.ps1` | screen-capture + P/Invoke heuristic (false positive) | review the content; add an exclusion for the repo folder |

## Decisions log (what worked / what didn't)

| Attempt | Result |
| --- | --- |
| MOK vendor var (`MokList` under shim lock GUID `605dab50-…`), 3 blob variants | **Rejected** — `Failed to resume 0x80070570`. Abandoned. |
| Append Sidero cert to `db` with `SigSize = 32 + cert` (extra X509_GUID inside signature data) | firmware accepted the db, boot looped (cert read as 16 zero bytes + cert) |
| Append Sidero cert to `db` with `SigSize = 16 + cert`, zero owner, both docs, R1 S fields + CRC | **Boots.** Shim + UKI verified; installer TUI with `SECUREBOOT ✓ True` |
| VmgsTool (microsoft/openvmm) | prebuilt artifacts need GitHub auth; not needed — byte-level editing proven sufficient |
| Black console + CPU 0% after the install reboot | **Not** a firmware/Secure Boot failure — the installed node has no TUI and its first boot is slow (kernel up ~1 min after power-on; node network up ~11 min in the v1.14.5 run). The db edit also survived the normal post-install firmware rewrite of the live `.vmgs` (hash `7cd79a914f836212`, db intact) and took effect **without** a VMMS restart (VM was Off at edit time). |
| etcd pre-stage loop `failed to build cluster arguments: timeout` after install | the single-CP node's **waiting state** for `talosctl bootstrap` (cf. siderolabs/talos#10806) — bootstrap resolved it in ~2 min, then `talosctl health --wait-timeout 120s` all-OK and `kubectl get nodes` Ready |
| Post-install ESP forensics | firmware boots device-only `Boot0001` → `\EFI\BOOT\BOOTX64.EFI` (0.2 MB **systemd-boot**, Sidero-signed) which auto-detects the 111 MB UKI `\EFI\Linux\Talos-v1.14.5.efi` (Sidero-signed, cmdline has `module.sig_enforce=1`); `loader.conf`'s `# systemd-boot configuration` header + systemd-boot's `Loader*` NVRAM vars (vendor `4a67b082`) prove the loader ran and selected the UKI — the boot chain needed no NVRAM intervention |
| Boot order: network (PXE) entry ahead of the disk on a fresh Gen 2 VM | every boot paid a PXE timeout before reaching the disk — after the install is verified, set `Drive, Network` (step 9): `Set-VMFirmware -BootOrder` with the `VMBootSource` objects reordered from `Get-VMFirmware` (bare strings don't bind), or the Hyper-V Manager *Boot Entries* list; no `.vmgs` edit needed |
