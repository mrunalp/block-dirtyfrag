## Summary

DirtyFrag is a Linux kernel privilege escalation that chains two page-cache
write vulnerabilities — **xfrm-ESP** and **rxrpc/rxkad** — to achieve root
from an unprivileged user on all major distributions.  The ESP path overwrites
`/usr/bin/su` with a root-shell ELF via XFRM Security Associations and
`splice()`.  The RxRPC path patches `/etc/passwd` to give root an empty
password via rxkad's in-place `pcbc(fcrypt)` decrypt on spliced page-cache
pages.

This document provides a **zero-reboot remediation** using a BPF LSM DaemonSet
that blocks both exploit paths:

- **AF\_RXRPC socket creation** — prevents the rxrpc/rxkad path entirely
- **UDP splice blocking** — prevents the xfrm-ESP path by blocking
  `MSG_SPLICE_PAGES` sends on UDP sockets (kernel 6.5+)
- **UDP\_ENCAP blocking** — fallback for pre-6.5 kernels that blocks
  `setsockopt(SOL_UDP, UDP_ENCAP)`

Other networking (UDP, TCP, AF\_ALG, AF\_NETLINK, etc.) is unaffected.

## Quick Start

```bash
# 1. Verify BPF LSM is enabled (All versions of RHEL CoreOS enable this by default)
oc debug node/<any-node> -- chroot /host cat /sys/kernel/security/lsm
# Must contain "bpf"

# 2. Deploy the blocker
oc apply -f daemonset.yaml

# 3. Verify
oc get pods -n dirtyfrag-mitigation-ebpf     # All nodes should show Running
oc logs -n dirtyfrag-mitigation-ebpf -l app=block-dirtyfrag
# Expected: "block-dirtyfrag: blocker active — AF_RXRPC + UDP splice + UDP_ENCAP blocked"
```

No reboots. No node drains. No pod restarts. Protection is immediate and
covers all processes on all nodes (100% coverage).

## Table of Contents

1. [How the Exploit Works](#how-the-exploit-works)
2. [Confirming Vulnerability with the Exploit Test](#confirming-vulnerability-with-the-exploit-test)
3. [BPF LSM DaemonSet Deployment](#bpf-lsm-daemonset-deployment)
4. [Post-Deployment Verification](#post-deployment-verification)
5. [Building from Source](#building-from-source)
6. [Removal](#removal)

---

## How the Exploit Works

DirtyFrag chains two independent kernel vulnerabilities:

### Path 1: xfrm-ESP Page-Cache Write

1. **User namespace** — `unshare(CLONE_NEWUSER | CLONE_NEWNET)` gains
   `CAP_NET_ADMIN` inside the new network namespace
2. **XFRM SA** — creates Security Associations with `IPPROTO_ESP` via
   `NETLINK_XFRM`, each carrying a 4-byte payload in the `seq_hi` field
3. **splice() + vmsplice()** — pins a page-cache page from `/usr/bin/su` into
   a pipe, then sends it as an ESP-in-UDP packet
4. **esp\_input() skip\_cow bypass** — the kernel's ESP receive path writes
   the `seq_hi` field back into the page-cache page without checking
   `SKBFL_SHARED_FRAG`, corrupting `/usr/bin/su` with a root-shell ELF

### Path 2: rxrpc/rxkad Page-Cache Write

1. **AF\_RXRPC socket** — creates an RxRPC client socket and initiates a call
   to a fake UDP server
2. **rxkad session key** — an attacker-chosen session key is installed via
   `add_key("rxrpc", ...)`
3. **splice() + vmsplice()** — pins a page-cache page from `/etc/passwd` into
   a pipe, then sends it as an RxRPC DATA packet
4. **rxkad\_verify\_packet\_1()** — the kernel's rxkad security layer performs
   an in-place `pcbc(fcrypt)` decrypt on the spliced page, overwriting the
   root entry in `/etc/passwd` with an empty password field

The two paths complement each other: ESP requires user namespaces (blocked by
AppArmor on Ubuntu), while RxRPC requires the `rxrpc.ko` module (loaded by
default only on Ubuntu).

---

## Confirming Vulnerability with the Exploit Test

A containerized exploit test is included.  It compiles the DirtyFrag exploit
(`exp.c`), runs it as an unprivileged user inside a privileged pod, and
reports whether the page cache was corrupted.

### Build and push the test image

```bash
podman build -f Dockerfile.test -t quay.io/<org>/block-dirtyfrag-test:latest .
podman push quay.io/<org>/block-dirtyfrag-test:latest
```

Update the image reference in `test/03-job.yaml` if using a different registry.

### Run the test

```bash
oc apply -f test/
```

Wait for the Job to complete and check the logs:

```bash
oc wait -n dirtyfrag-test job/dirtyfrag-exploit-test \
  --for=condition=Complete --timeout=120s
oc logs -n dirtyfrag-test -l job-name=dirtyfrag-exploit-test
```

**On a vulnerable cluster** (no blocker deployed):

```
=== DirtyFrag Exploit Test ===
Kernel: 5.14.0-687.5.1.el9_8.x86_64
Target: /usr/bin/su

SHA256 before: 8969560ae8e6e21c6184c1451f59418822ee69dd5d946d71987b55236bbc0feb

--- Running exploit as uid=1000 (testuser) ---

[su] installed 48 xfrm SAs
[su] wrote 192 bytes to /usr/bin/su starting at 0x0
[su] /usr/bin/su page-cache patched (entry 0x78 = shellcode)

--- Exploit exit code: 124 ---

SHA256 after:  d42402457db3ea075352e9b76c622d3ff0bb89326e6f3511d5279b0e550ead31
Bytes at 0x78: 31ff31f631c0b06a

=== Result ===
VULNERABLE — page cache corrupted, shellcode injected into /usr/bin/su

The kernel is vulnerable to DirtyFrag (xfrm-ESP page-cache write).
Deploy the BPF LSM blocker: oc apply -f daemonset.yaml
```

**After deploying the blocker:**

```
=== DirtyFrag Exploit Test ===
Kernel: 5.14.0-687.5.1.el9_8.x86_64
Target: /usr/bin/su

SHA256 before: 8969560ae8e6e21c6184c1451f59418822ee69dd5d946d71987b55236bbc0feb

--- Running exploit as uid=1000 (testuser) ---

[su] installed 48 xfrm SAs
[su] do_one_write #0 at off=0x0 failed
[su] corruption stage failed (status=0x200)
dirtyfrag: failed (rc=1)

--- Exploit exit code: 1 ---

SHA256 after:  8969560ae8e6e21c6184c1451f59418822ee69dd5d946d71987b55236bbc0feb
Bytes at 0x78: 0300000004000000

=== Result ===
BLOCKED — exploit failed, page cache intact

The BPF LSM blocker is working. The exploit could not corrupt /usr/bin/su.
```

### Clean up

```bash
oc delete namespace dirtyfrag-test
```

---

## BPF LSM DaemonSet Deployment

The BPF LSM approach uses three hooks for coverage across kernel versions:

- `lsm/socket_create` — blocks all `AF_RXRPC` (family 33) socket creation
- `lsm/socket_sendmsg` — blocks `MSG_SPLICE_PAGES` sends on UDP sockets
  (kernel 6.5+, targets the splice primitive directly)
- `lsm/socket_setsockopt` — blocks `setsockopt(SOL_UDP, UDP_ENCAP)` (pre-6.5
  fallback, blocks UDP ESP encapsulation setup)

### Prerequisites

BPF LSM must be enabled. RHEL CoreOS 9.8 (OCP 4.22) has it enabled by default.
Verify with:

```bash
oc debug node/<any-node> -- chroot /host cat /sys/kernel/security/lsm
```

Expected output includes `bpf`:

```
lockdown,capability,landlock,yama,selinux,bpf
```

If `bpf` is **not** present, a one-time MachineConfig is needed (this is the
only scenario requiring a reboot):

```bash
oc apply -f machineconfig-enable-bpf-lsm.yaml
```

### Step 1: Deploy

```bash
oc apply -f daemonset.yaml
```

### Step 2: Wait for pods to start on all nodes

```bash
oc get pods -n dirtyfrag-mitigation-ebpf -o wide
```

Expected: one pod per node, all `Running`.

### Step 3: Verify the blocker is active

```bash
oc logs -n dirtyfrag-mitigation-ebpf -l app=block-dirtyfrag
```

Expected:

```
block-dirtyfrag: blocker active — AF_RXRPC + UDP splice + UDP_ENCAP blocked
```

---

## Post-Deployment Verification

Re-run the exploit test from the [Confirming Vulnerability](#confirming-vulnerability-with-the-exploit-test) section:

```bash
oc delete namespace dirtyfrag-test 2>/dev/null
oc apply -f test/
oc wait -n dirtyfrag-test job/dirtyfrag-exploit-test \
  --for=condition=Complete --timeout=120s
oc logs -n dirtyfrag-test -l job-name=dirtyfrag-exploit-test
```

The output should show `BLOCKED — exploit failed, page cache intact`.

The DaemonSet logs will show the blocked attempt:

```bash
oc logs -n dirtyfrag-mitigation-ebpf -l app=block-dirtyfrag
```

```
block-dirtyfrag: BLOCKED UDP_ENCAP (ESP) pid=24212 comm=exp time=2026-05-07 23:44:32
```

---

## Building from Source

### Blocker image

```bash
podman build -t quay.io/<org>/block-dirtyfrag:latest .
podman push quay.io/<org>/block-dirtyfrag:latest
```

Multi-stage build: Fedora with clang/bpftool/libbpf-devel for compilation,
UBI 9 minimal for the runtime image.

### Exploit test image

```bash
podman build -f Dockerfile.test -t quay.io/<org>/block-dirtyfrag-test:latest .
podman push quay.io/<org>/block-dirtyfrag-test:latest
```

Multi-stage build: UBI 9 with gcc for compilation, UBI 9 for runtime with a
non-root `testuser` (uid=1000) and a wrapper script that runs the exploit and
reports results.

### File layout

```
block_dirtyfrag.bpf.c     # BPF kernel program (3 LSM hooks)
block_dirtyfrag.c          # Userspace loader (libbpf skeleton)
block_dirtyfrag.h          # Shared event struct
Makefile                   # Blocker build pipeline
Dockerfile                 # Blocker image
Dockerfile.test            # Exploit test image
exp.c                      # DirtyFrag exploit source
daemonset.yaml             # Namespace + DaemonSet manifest
machineconfig-enable-bpf-lsm.yaml
test/
  01-namespace.yaml        # Privileged test namespace
  02-rolebinding.yaml      # SCC grant
  03-job.yaml              # Exploit test Job
  run-exploit-test.sh      # Test wrapper script
trigger-test.py            # Quick blocker validation
verify-subsystems.py       # Comprehensive subsystem check
testing-notes.md           # Detailed testing journal
cluster-assessment.md      # Cluster vulnerability assessment
```

---

## Removal

Deleting the DaemonSet immediately removes the mitigation on all nodes:

```bash
oc delete -f daemonset.yaml
# or
oc delete namespace dirtyfrag-mitigation-ebpf
```

The BPF program detaches automatically when the loader process exits. No reboot
or pod restart is needed.
