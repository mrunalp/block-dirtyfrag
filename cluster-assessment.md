# DirtyFrag Cluster Assessment

**Cluster:** ci-ln-sh20r6t-72292-hjsdt
**Date:** 2026-05-07
**Kernel:** 5.14.0-687.5.1.el9_8.x86_64 (RHEL 9.8)
**Nodes:** 3 masters + 3 workers

## Exploit Module Availability

| Module | Status | Path | Notes |
|--------|--------|------|-------|
| esp4   | Loadable module, **not loaded** | `/lib/modules/.../net/ipv4/esp4.ko.xz` | Could be loaded on demand by XFRM SA creation |
| esp6   | Loadable module, **not loaded** | `/lib/modules/.../net/ipv6/esp6.ko.xz` | Could be loaded on demand by XFRM SA creation |
| rxrpc  | **Not available** | — | Module does not exist on this kernel |

## Exploit Path Assessment

| Path | Risk | Reason |
|------|------|--------|
| xfrm-ESP (overwrites `/usr/bin/su`) | **Possible** | esp4/esp6 modules exist on disk and could be autoloaded |
| rxrpc/rxkad (patches `/etc/passwd`) | **Not exploitable** | rxrpc module is not shipped with this kernel |

## BPF LSM Readiness

| Requirement | Status |
|-------------|--------|
| BPF LSM enabled (`/sys/kernel/security/lsm`) | Yes — `lockdown,capability,landlock,yama,selinux,bpf` |
| `security_xfrm_state_alloc` symbol in kernel | Yes — `CONFIG_SECURITY_NETWORK_XFRM=y` confirmed via `/proc/kallsyms` |
| BTF available (`/sys/kernel/btf/vmlinux`) | Yes — mounted by DaemonSet |

## Mitigation Options

### Option 1: modprobe blacklist (no reboot required)

Blacklist the vulnerable modules on all nodes:

```bash
sh -c "printf 'install esp4 /bin/false\ninstall esp6 /bin/false\n' > /etc/modprobe.d/dirtyfrag.conf; rmmod esp4 esp6 2>/dev/null; true"
```

- Prevents esp4/esp6 from loading.
- rxrpc is already absent — no action needed.
- Must be applied per-node (MachineConfig for OpenShift).
- Breaks IPsec if in use.

### Option 2: BPF LSM DaemonSet (no reboot required)

Deploy `block-dirtyfrag` DaemonSet:

```bash
oc apply -f daemonset.yaml
```

- `lsm/socket_create` hook blocks AF_RXRPC sockets (defense in depth — module is absent but hook covers future kernels).
- `lsm/xfrm_state_alloc` hook blocks XFRM ESP state creation even if esp4/esp6 modules are loaded.
- Zero-reboot, immediate coverage on all nodes.
- Automatically removed when DaemonSet is deleted.

### Recommendation

On this cluster, the **ESP path is the only viable attack vector**. The BPF LSM DaemonSet is the preferred mitigation — it blocks ESP state creation at the LSM level without needing to manage modprobe configs across nodes, and it provides defense-in-depth for the rxrpc path on kernels where that module may be available.
