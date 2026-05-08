## Summary

DirtyFrag is a Linux kernel privilege escalation that chains two page-cache
write vulnerabilities — **xfrm-ESP** and **rxrpc/rxkad** — to achieve root
from an unprivileged user on all major distributions.  The ESP path overwrites
`/usr/bin/su` with a root-shell ELF via XFRM Security Associations and
`splice()`.  The RxRPC path patches `/etc/passwd` to give root an empty
password via rxkad's in-place `pcbc(fcrypt)` decrypt on spliced page-cache
pages.

This document provides a **zero-reboot remediation** using a BPF LSM DaemonSet
with three layers of defense:

- **AF\_RXRPC socket creation** — prevents the rxrpc/rxkad path entirely
- **NETLINK\_XFRM from containers** — blocks XFRM socket creation from
  non-init user or PID namespaces, covering both privileged and non-privileged
  containers while leaving host-level IPsec/VPN unaffected
- **UDP splice blocking** — blocks `MSG_SPLICE_PAGES` sends on UDP sockets
  (kernel 6.5+), closing the edge case where a container with `hostPID` +
  `hostNetwork` + `CAP_NET_ADMIN` bypasses namespace checks

Other networking (UDP, TCP, AF\_ALG, AF\_NETLINK for non-XFRM, etc.) is
completely unaffected.

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
# Expected: "block-dirtyfrag: blocker active — AF_RXRPC + XFRM-from-container + UDP-splice blocked"
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

[su] add_xfrm_sa #0 failed
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

The BPF LSM approach uses three layers of defense:

| Layer | Hook | What it blocks | Coverage |
|-------|------|---------------|----------|
| 1 | `lsm/socket_create` | AF\_RXRPC sockets | rxrpc/rxkad path (all kernels) |
| 2 | `lsm/socket_create` | NETLINK\_XFRM from userns level > 0 or pidns level > 0 | ESP path from containers (all kernels) |
| 3 | `lsm/socket_sendmsg` | MSG\_SPLICE\_PAGES on UDP | ESP path from hostPID+hostNetwork+CAP\_NET\_ADMIN (kernel 6.5+) |

Layer 2 checks `task->cred->user_ns->level` and
`task->nsproxy->pid_ns_for_children->level` via BPF CO-RE.  This catches both
non-privileged containers (userns level > 0 after `unshare`) and privileged
containers (pidns level > 0).  Host-level IPsec/VPN runs at level 0 for both
namespaces and is completely unaffected.

All layers skip kernel-internal socket creation (`kern=1`) to avoid
interfering with legitimate kernel operations like network namespace setup,
which creates internal NETLINK\_XFRM sockets.

Layer 3 is defense-in-depth for the edge case where a container has `hostPID`
\+ `hostNetwork` + `CAP_NET_ADMIN` (both namespace levels are 0).  On pre-6.5
kernels, this layer is a harmless no-op since splice-to-socket uses the
`sendpage` path instead of `sendmsg`.

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
block-dirtyfrag: blocker active — AF_RXRPC + XFRM-from-container + UDP-splice blocked
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
block-dirtyfrag: BLOCKED XFRM from container pid=74644 comm=dirtyfrag-exp time=2026-05-08 15:14:58
```

---

## Testing Individual Defense Layers

A comprehensive Python test (`test/test-all-layers.py`) exercises each BPF
hook independently without running the full exploit.

### From a privileged container

Deploy the test script into a privileged pod:

```bash
oc create namespace layer-test
oc apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: system:openshift:scc:privileged
  namespace: layer-test
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: system:openshift:scc:privileged
subjects:
- kind: ServiceAccount
  name: default
  namespace: layer-test
EOF

oc create configmap layer-test-script -n layer-test \
  --from-file=test-all-layers.py=test/test-all-layers.py

oc apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: layer-test
  namespace: layer-test
spec:
  restartPolicy: Never
  containers:
  - name: test
    image: registry.fedoraproject.org/fedora:latest
    command: ["/bin/bash", "-c",
      "dnf install -y python3 >/dev/null 2>&1 && python3 /scripts/test-all-layers.py"]
    securityContext:
      privileged: true
    volumeMounts:
    - name: script
      mountPath: /scripts
      readOnly: true
  volumes:
  - name: script
    configMap:
      name: layer-test-script
EOF

oc wait -n layer-test pod/layer-test --for=condition=Ready --timeout=120s || true
oc logs -n layer-test layer-test
```

Expected output with blocker active:

```
=== BPF LSM Defense Layer Tests ===
uid=0 pid=1
SELinux: system_u:system_r:spc_t:s0

--- Layer 1: AF_RXRPC socket blocking ---
  [PASS]  AF_RXRPC socket from container: blocked (expected: blocked)

--- Layer 2a: NETLINK_XFRM from container pidns ---
  [PASS]  NETLINK_XFRM without unshare (pidns > 0): blocked (expected: blocked)

--- Layer 2b: NETLINK_XFRM after unshare (userns > 0) ---
  [SKIP]  unshare(NEWUSER|NEWNET) failed — cannot test userns check

--- Layer 3: splice-to-UDP (MSG_SPLICE_PAGES) ---
  [INFO]  splice-to-UDP allowed — expected on pre-6.5 kernels (sendpage path, hook is no-op)

--- Sanity checks (should all be allowed) ---
  [PASS]  AF_INET TCP: allowed (expected: allowed)
  [PASS]  AF_INET UDP: allowed (expected: allowed)
  [PASS]  AF_INET6 TCP: allowed (expected: allowed)
  [PASS]  AF_NETLINK (non-XFRM): allowed (expected: allowed)

--- Host IPsec passthrough (NETLINK_XFRM at level 0) ---
  [SKIP]  Running inside a container — cannot test host-level XFRM
          Run this script via 'oc debug node/<node>' to test

=== Summary: 6 passed, 0 failed, 3 skipped (out of 9) ===
```

Layer 2b is skipped because Python's `unshare` via ctypes encounters memory
allocation issues in containers.  Layer 3 is informational on pre-6.5 kernels
(the hook is a harmless no-op).

### Testing Layer 2b with the C test

Layer 2b (userns-level XFRM blocking after `unshare`) requires a C binary
since Python's ctypes has memory issues with `unshare` in containers.  Build
and run `test/test_layer2b.c`:

```bash
# Build (from the repo root)
podman run --rm -v ./test:/build:Z registry.access.redhat.com/ubi9/ubi:latest \
  bash -c 'dnf install -y gcc >/dev/null 2>&1 && gcc -O0 -Wall -o /build/test_layer2b /build/test_layer2b.c'

# Deploy into a privileged pod and run as non-root
oc create configmap layer2b-binary -n layer-test \
  --from-file=test_layer2b=test/test_layer2b

oc apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: layer2b-test
  namespace: layer-test
spec:
  restartPolicy: Never
  containers:
  - name: test
    image: quay.io/mrunalp/block-dirtyfrag-test:latest
    command: ["bash", "-c",
      "cp /config/test_layer2b /tmp/test_layer2b && chmod +x /tmp/test_layer2b && runuser -u testuser -- /tmp/test_layer2b"]
    securityContext:
      privileged: true
    volumeMounts:
    - name: binary
      mountPath: /config
      readOnly: true
  volumes:
  - name: binary
    configMap:
      name: layer2b-binary
      defaultMode: 0755
EOF

oc logs -n layer-test layer2b-test
```

Expected output with blocker active:

```
uid=1000 pid=4
Step 1: unshare(NEWUSER|NEWNET)
  OK — userns level > 0

Step 2: socket(AF_NETLINK, SOCK_RAW, NETLINK_XFRM)
  BLOCKED: Operation not permitted (errno=1)
  Layer 2b is working!
Child exit code: 0
```

Without the blocker, Step 2 shows `ALLOWED`.

### From the host (verifying IPsec passthrough)

Run via `oc debug` to confirm host-level XFRM is unaffected:

```bash
oc debug node/<any-node> -- chroot /host python3 -c "
import socket
AF_NETLINK = 16
NETLINK_XFRM = 6
try:
    s = socket.socket(AF_NETLINK, socket.SOCK_RAW, NETLINK_XFRM)
    s.close()
    print('PASS: NETLINK_XFRM from host (level 0) — ALLOWED, IPsec works')
except OSError as e:
    print(f'FAIL: NETLINK_XFRM from host — BLOCKED: {e}')
"
```

Expected:

```
PASS: NETLINK_XFRM from host (level 0) — ALLOWED, IPsec works
```

### Clean up

```bash
oc delete namespace layer-test
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
block_dirtyfrag.bpf.c     # BPF kernel program (3 defense layers)
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
  test-all-layers.py       # Per-layer defense validation (Python)
  test_layer2b.c           # Layer 2b userns XFRM test (C)
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
