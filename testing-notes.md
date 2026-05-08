# DirtyFrag BPF LSM Blocker — Testing Notes

**Cluster:** ci-ln-sh20r6t-72292-hjsdt (3 masters, 3 workers)
**Kernel:** 5.14.0-687.5.1.el9_8.x86_64 (RHEL 9.8)
**Date:** 2026-05-07

## Cluster Assessment

Before developing the blocker, we assessed the cluster's exposure:

| Module | Status |
|--------|--------|
| esp4   | Loadable module on disk, not loaded |
| esp6   | Loadable module on disk, not loaded |
| rxrpc  | **Not available** — module does not exist on this kernel |

- BPF LSM enabled: `lockdown,capability,landlock,yama,selinux,bpf`
- `security_xfrm_state_alloc` symbol present in `/proc/kallsyms`
- Only the ESP exploit path is viable on this cluster

## Iteration 1: `xfrm_state_alloc` hook

**Approach:** Hook `lsm/socket_create` (AF_RXRPC) + `lsm/xfrm_state_alloc` (IPPROTO_ESP via CO-RE).

**Result:** AF_RXRPC blocking worked. ESP blocking did NOT work.

Both BPF programs loaded and attached successfully (prog IDs 133, 134 in
`/proc/*/fdinfo/*`), but the `xfrm_state_alloc` program had `run_time_ns: 0`
— it never fired.

**Root cause:** On kernel 5.14, `security_xfrm_state_alloc()` in
`xfrm_state_construct()` is only called when the `XFRMA_SEC_CTX` netlink
attribute is present. The exploit does not set `XFRMA_SEC_CTX`, so the
security hook is never reached. The exploit's `add_xfrm_sa()` creates SAs
with auth/enc/encap/ESN attributes but no security context.

Verified with `ip xfrm state add ... proto esp` — succeeded with exit code 0,
no BLOCKED event in DaemonSet logs.

## Iteration 2: `socket_setsockopt` hook

**Approach:** Replace `xfrm_state_alloc` with `lsm/socket_setsockopt`,
blocking `level == SOL_UDP (17) && optname == UDP_ENCAP (100)`.

**Result:** Both hooks worked.

```
=== Test 1: AF_RXRPC socket ===
  BLOCKED — [Errno 1] Operation not permitted

=== Test 2: UDP_ENCAP setsockopt ===
  BLOCKED — [Errno 1] Operation not permitted

=== Test 3: Normal TCP (should be allowed) ===
  ALLOWED

=== Test 4: Normal UDP (should be allowed) ===
  ALLOWED
```

DaemonSet logs confirmed both event types:
```
block-dirtyfrag: BLOCKED AF_RXRPC socket pid=23199 comm=python3
block-dirtyfrag: BLOCKED XFRM ESP state pid=23199 comm=python3
```

K8s test pod also confirmed: `RESULT: ALL EXPLOIT PATHS BLOCKED`.

**Downside:** Blocking `UDP_ENCAP` entirely also blocks L2TP and IPsec NAT-T.

## Iteration 3: `socket_sendmsg` hook (from PR #18)

Adopted the approach from
[openshift/block-copyfail#18](https://github.com/openshift/block-copyfail/pull/18):
hook `lsm/socket_sendmsg` and block `MSG_SPLICE_PAGES` on UDP sockets. This
targets the exact exploit primitive (splice-to-UDP zero-copy sends) with
minimal side effects.

**Result:** AF_RXRPC blocking worked. UDP splice blocking did NOT work on
this kernel.

**Root cause:** `MSG_SPLICE_PAGES` was introduced in kernel 6.5. On 5.14,
splice-to-socket uses the `sendpage` path (`kernel_sendpage()` →
`udp_sendpage()`), which does not go through `sendmsg` at all. The BPF
`socket_sendmsg` hook never fires.

PR #18 acknowledges this: "On kernels without MSG_SPLICE_PAGES (pre-6.5),
the hook is a harmless no-op."

## Iteration 4: Three hooks (final)

**Approach:** Use all three hooks for complete coverage:

1. `lsm/socket_create` — blocks AF_RXRPC sockets (rxrpc/rxkad path)
2. `lsm/socket_sendmsg` — blocks `MSG_SPLICE_PAGES` on UDP (ESP path, kernel 6.5+)
3. `lsm/socket_setsockopt` — blocks `setsockopt(SOL_UDP, UDP_ENCAP)` (ESP path, pre-6.5 fallback)

On kernel 6.5+, hook 2 provides precise blocking (only splice-to-UDP). On
pre-6.5 kernels, hook 3 provides the fallback (blocks all UDP encapsulation).

**Result:** All hooks loaded and the exploit was fully blocked.

## Exploit Verification

### Without blocker

Compiled `exp.c` in a UBI9 container, copied to a privileged pod, ran as
uid=1000 via `runuser`:

```
[su] installed 48 xfrm SAs
[su] wrote 192 bytes to /usr/bin/su starting at 0x0
[su] /usr/bin/su page-cache patched (entry 0x78 = shellcode)
[root@exploit-test /]#
```

- `/usr/bin/su` page cache corrupted: hash changed from `8969560a...` to `d4240245...`
- Bytes at offset 0x78: `31 ff 31 f6 31 c0 b0 6a` (root-shell shellcode: `xor edi,edi; xor esi,esi; xor eax,eax; mov al,0x6a`)
- Root shell spawned successfully

### With blocker (3 hooks)

After deploying the updated DaemonSet and dropping page caches
(`echo 1 > /proc/sys/vm/drop_caches`), re-ran the same exploit:

```
[su] installed 48 xfrm SAs
[su] do_one_write #0 at off=0x0 failed
[su] corruption stage failed (status=0x200)
dirtyfrag: failed (rc=1)
```

- The exploit installed XFRM SAs (netlink is not blocked) but failed at
  `do_one_write` because `setsockopt(SOL_UDP, UDP_ENCAP)` returned `EPERM`
- `/usr/bin/su` hash unchanged: `8969560a...` (original)
- Bytes at offset 0x78: `03 00 00 00 04 00 00 00` (original ELF content)
- DaemonSet log: `BLOCKED UDP_ENCAP (ESP) pid=24212 comm=exp`

## Key Findings

1. **`xfrm_state_alloc` is unreliable** — the LSM hook is only called when
   `XFRMA_SEC_CTX` is present, which the exploit does not use.

2. **`socket_sendmsg` + `MSG_SPLICE_PAGES` is precise but kernel-version-dependent** —
   only works on 6.5+ where splice-to-socket goes through sendmsg.

3. **`socket_setsockopt` blocking `UDP_ENCAP` works on all kernels** — the
   exploit must call this setsockopt to enable ESP-in-UDP reception. Broader
   side effects (L2TP, IPsec NAT-T) but reliable.

4. **Combining hooks 2 and 3 gives best coverage** — precise on new kernels,
   reliable fallback on old ones. On 6.5+, both fire but the sendmsg hook
   blocks first (before the packet reaches the ESP receiver).

5. **Page cache corruption persists across pods on the same node** — must
   drop caches (`echo 1 > /proc/sys/vm/drop_caches`) between test runs.
