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
- **UDP\_ENCAP setsockopt** — prevents the xfrm-ESP path by blocking the
  UDP ESP encapsulation needed to receive ESP-in-UDP packets

Other networking (UDP, TCP, AF\_ALG, AF\_NETLINK, etc.) is unaffected.

## Quick Start

```bash
# 1. Verify BPF LSM is enabled (All versions of RHEL CoreOS enable this by default)
oc debug node/<any-node> -- chroot /host cat /sys/kernel/security/lsm
# Must contain "bpf"

# 2. Deploy the namespace and grant privileged SCC
oc apply -f daemonset.yaml

# 3. DaemonSet pods will start automatically on all nodes

# 4. Verify
oc get pods -n dirtyfrag-mitigation-ebpf     # All nodes should show Running
oc logs -n dirtyfrag-mitigation-ebpf -l app=block-dirtyfrag
# Expected: "block-dirtyfrag: blocker active — AF_RXRPC sockets and UDP_ENCAP blocked"
```

No reboots. No node drains. No pod restarts. Protection is immediate and
covers all processes on all nodes (100% coverage).

## Table of Contents

1. [How the Exploit Works](#how-the-exploit-works)
2. [Confirming Vulnerability on Your Cluster](#confirming-vulnerability-on-your-cluster)
3. [BPF LSM DaemonSet Deployment](#bpf-lsm-daemonset-deployment)
4. [Post-Deployment Verification](#post-deployment-verification)
5. [Building the Image from Source](#building-the-image-from-source)
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

## Confirming Vulnerability on Your Cluster

Create a new `dirtyfrag-test` namespace on your cluster and run the test
script by applying the manifests in [the `test` directory](test):

```bash
oc apply -f test
```

Check the results:

```bash
oc wait pod/dirtyfrag-test -n dirtyfrag-test \
  --for=jsonpath='{.status.phase}'=Succeeded --timeout=120s
oc -n dirtyfrag-test logs -l app=dirtyfrag-test
```

**On a vulnerable cluster** you will see:

```
=== DirtyFrag Vulnerability Test ===

--- Test 1: AF_RXRPC socket creation ---
  AF_RXRPC socket: ALLOWED

--- Test 2: XFRM netlink socket ---
  XFRM netlink socket: ALLOWED

--- Test 3: UDP ESP encapsulation ---
  UDP_ENCAP_ESPINUDP: ALLOWED

=== Summary ===
  rxrpc/rxkad path: VULNERABLE (AF_RXRPC sockets allowed)
  xfrm-ESP path:    POTENTIALLY VULNERABLE (XFRM + UDP_ENCAP allowed)

RESULT: AT LEAST ONE PATH AVAILABLE — system may be vulnerable
```

### Clean up

```bash
oc delete namespace dirtyfrag-test
```

---

## BPF LSM DaemonSet Deployment

The BPF LSM approach uses two hooks:

- `socket_create` — blocks all `AF_RXRPC` (family 33) socket creation
- `socket_setsockopt` — blocks `setsockopt(SOL_UDP, UDP_ENCAP)`, preventing
  the UDP ESP encapsulation required by the xfrm-ESP exploit path

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

### Step 1: Create the namespace, grant the SCC, and deploy

```bash
oc apply -f daemonset.yaml
```

### Step 2: Wait for pods to start on all nodes

```bash
oc get pods -n dirtyfrag-mitigation-ebpf -o wide
```

Expected: one pod per node, all `Running`:

```
NAME                          READY   STATUS    AGE   NODE
block-dirtyfrag-2jhzf         1/1     Running   34s   ci-...-master-2
block-dirtyfrag-4dfq7         1/1     Running   34s   ci-...-master-1
block-dirtyfrag-c2ts8         1/1     Running   34s   ci-...-worker-c
block-dirtyfrag-ctblk         1/1     Running   34s   ci-...-worker-a
block-dirtyfrag-m26sx         1/1     Running   34s   ci-...-worker-b
block-dirtyfrag-xsh6d         1/1     Running   34s   ci-...-master-0
```

### Step 3: Verify the blocker is active

```bash
oc logs -n dirtyfrag-mitigation-ebpf -l app=block-dirtyfrag
```

Expected:

```
block-dirtyfrag: blocker active — AF_RXRPC sockets and XFRM ESP states blocked
```

---

## Post-Deployment Verification

Re-run the same test from the [Confirming Vulnerability](#confirming-vulnerability-on-your-cluster) section.

**After deploying the BPF LSM DaemonSet**, the output will be:

```
=== DirtyFrag Vulnerability Test ===

--- Test 1: AF_RXRPC socket creation ---
  AF_RXRPC socket: BLOCKED — [Errno 1] Operation not permitted

--- Test 2: XFRM netlink socket ---
  XFRM netlink socket: ALLOWED

--- Test 3: UDP ESP encapsulation ---
  UDP_ENCAP_ESPINUDP: ALLOWED

=== Summary ===
  rxrpc/rxkad path: MITIGATED (AF_RXRPC sockets blocked)
  xfrm-ESP path:    MITIGATED

RESULT: ALL EXPLOIT PATHS BLOCKED — mitigation active
```

The DaemonSet logs will show blocked attempts:

```bash
oc logs -n dirtyfrag-mitigation-ebpf -l app=block-dirtyfrag
```

```
block-dirtyfrag: blocker active — AF_RXRPC sockets and UDP_ENCAP blocked
block-dirtyfrag: BLOCKED AF_RXRPC socket pid=16777    comm=python3 time=2026-05-07 10:23:45
```

### Verifying Other Subsystems Are Unaffected

Run `verify-subsystems.py` on a node to confirm that only the exploit
subsystems are blocked:

```bash
oc debug node/<any-node> -- chroot /host python3 -c "
import socket
AF_RXRPC = 33
tests = [
    ('AF_RXRPC', AF_RXRPC, socket.SOCK_DGRAM, socket.AF_INET),
    ('AF_INET TCP', socket.AF_INET, socket.SOCK_STREAM, 0),
    ('AF_INET UDP', socket.AF_INET, socket.SOCK_DGRAM, 0),
    ('AF_INET6 TCP', socket.AF_INET6, socket.SOCK_STREAM, 0),
    ('AF_NETLINK', socket.AF_NETLINK, socket.SOCK_RAW, 0),
]
for label, fam, st, proto in tests:
    try:
        s = socket.socket(fam, st, proto)
        print(f'  ALLOWED  {label}')
        s.close()
    except OSError as e:
        print(f'  BLOCKED  {label} -- {e}')
"
```

Expected output:

```
  BLOCKED  AF_RXRPC -- [Errno 1] Operation not permitted
  ALLOWED  AF_INET TCP
  ALLOWED  AF_INET UDP
  ALLOWED  AF_INET6 TCP
  ALLOWED  AF_NETLINK
```

---

## Building the Image from Source

```
block_dirtyfrag.bpf.c     # BPF kernel program (two LSM hooks)
block_dirtyfrag.c          # Userspace loader (libbpf skeleton)
block_dirtyfrag.h          # Shared event struct
Makefile                   # Build pipeline
Dockerfile                 # Multi-stage build
daemonset.yaml             # Namespace + DaemonSet manifest
trigger-test.py            # Quick validation script
verify-subsystems.py       # Comprehensive subsystem verification
```

Build and push:

```bash
podman build -t quay.io/<org>/block-dirtyfrag:latest .
podman push quay.io/<org>/block-dirtyfrag:latest
```

The Dockerfile uses a multi-stage build: Fedora with clang/bpftool/libbpf-devel
for compilation, UBI 9 minimal for the runtime image.

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
