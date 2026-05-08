#!/usr/bin/env python3
"""Test all three BPF LSM defense layers independently.

Run from a privileged container (for unshare capability) or via oc debug.
Reports which layers are active and whether host-level IPsec is unaffected.
"""
import socket
import ctypes
import os
import sys

AF_RXRPC = 33
AF_NETLINK = 16
NETLINK_XFRM = 6
CLONE_NEWUSER = 0x10000000
CLONE_NEWNET = 0x40000000
SOL_UDP = 17
SPLICE_F_MOVE = 1

libc = ctypes.CDLL(None, use_errno=True)

passed = 0
failed = 0
skipped = 0

def check(label, condition, expected):
    global passed, failed
    status = "PASS" if condition == expected else "FAIL"
    if condition == expected:
        passed += 1
    else:
        failed += 1
    result = "blocked" if not condition else "allowed"
    want = "blocked" if not expected else "allowed"
    print(f"  [{status}]  {label}: {result} (expected: {want})")

print("=== BPF LSM Defense Layer Tests ===")
print(f"uid={os.getuid()} pid={os.getpid()}")
try:
    with open("/proc/self/attr/current") as f:
        print(f"SELinux: {f.read().strip()}")
except:
    pass
print()

# =====================================================================
# Layer 1: AF_RXRPC socket blocking
# =====================================================================
print("--- Layer 1: AF_RXRPC socket blocking ---")

def try_rxrpc():
    try:
        s = socket.socket(AF_RXRPC, socket.SOCK_DGRAM, socket.AF_INET)
        s.close()
        return True
    except OSError:
        return False

# AF_RXRPC should be blocked (EPERM from BPF, or EAFNOSUPPORT if module absent)
rxrpc_allowed = try_rxrpc()
check("AF_RXRPC socket from container", rxrpc_allowed, False)

print()

# =====================================================================
# Layer 2a: XFRM from non-init pidns (privileged container)
# =====================================================================
print("--- Layer 2a: NETLINK_XFRM from container pidns ---")

def try_xfrm_direct():
    """Try NETLINK_XFRM without unshare — tests pidns level check."""
    try:
        s = socket.socket(AF_NETLINK, socket.SOCK_RAW, NETLINK_XFRM)
        s.close()
        return True
    except OSError:
        return False

# Detect if running in a container by checking SELinux context and PID
try:
    with open("/proc/self/attr/current") as f:
        selinux_ctx = f.read().strip()
    in_container = ("container_t" in selinux_ctx or "spc_t" in selinux_ctx)
except:
    in_container = os.getpid() == 1  # PID 1 is a strong container signal

if in_container:
    xfrm_direct = try_xfrm_direct()
    check("NETLINK_XFRM without unshare (pidns > 0)", xfrm_direct, False)
elif not in_container:
    print("  [SKIP]  Running in init pidns (host) — pidns check not applicable")
    skipped += 1
else:
    print("  [SKIP]  Could not determine pidns depth")
    skipped += 1

print()

# =====================================================================
# Layer 2b: XFRM from non-init userns (after unshare)
# =====================================================================
print("--- Layer 2b: NETLINK_XFRM after unshare (userns > 0) ---")

def try_xfrm_after_unshare():
    """Fork, unshare into new userns/netns, try NETLINK_XFRM."""
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(r)
        rc = libc.unshare(CLONE_NEWUSER | CLONE_NEWNET)
        if rc < 0:
            os.write(w, b"unshare_fail")
            os.close(w)
            os._exit(1)
        try:
            s = socket.socket(AF_NETLINK, socket.SOCK_RAW, NETLINK_XFRM)
            s.close()
            os.write(w, b"allowed")
        except OSError:
            os.write(w, b"blocked")
        os.close(w)
        os._exit(0)
    os.close(w)
    result = os.read(r, 64).decode()
    os.close(r)
    os.waitpid(pid, 0)
    return result

userns_result = try_xfrm_after_unshare()
if userns_result == "unshare_fail":
    print("  [SKIP]  unshare(NEWUSER|NEWNET) failed — cannot test userns check")
    skipped += 1
else:
    check("NETLINK_XFRM after unshare (userns > 0)",
          userns_result == "allowed", False)

print()

# =====================================================================
# Layer 3: MSG_SPLICE_PAGES on UDP (6.5+ only)
# =====================================================================
print("--- Layer 3: splice-to-UDP (MSG_SPLICE_PAGES) ---")

def try_splice_to_udp():
    """Try splice from pipe to UDP socket. On 6.5+ kernels with the
    sendmsg hook, this should be blocked. On pre-6.5, splice-to-socket
    uses sendpage (not sendmsg), so the hook is a no-op."""
    try:
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
        udp.connect(("127.0.0.1", 9))  # discard port
        pr, pw = os.pipe()
        os.write(pw, b"test")
        os.close(pw)
        # splice pipe -> udp socket
        n = libc.splice(pr, None, udp.fileno(), None, 4, SPLICE_F_MOVE)
        err = ctypes.get_errno() if n < 0 else 0
        os.close(pr)
        udp.close()
        if n < 0:
            return "blocked", err
        return "allowed", 0
    except OSError as e:
        return "blocked", e.errno

# Check if kernel has splice_to_socket (6.5+ indicator)
has_splice_to_socket = False
try:
    with open("/proc/kallsyms") as f:
        for line in f:
            if " splice_to_socket\n" in line:
                has_splice_to_socket = True
                break
except PermissionError:
    pass

result, errno_val = try_splice_to_udp()
if has_splice_to_socket:
    check("splice pipe->UDP (kernel has splice_to_socket)",
          result == "allowed", False)
else:
    if result == "blocked":
        print(f"  [INFO]  splice-to-UDP blocked (errno={errno_val}) — "
              f"may be kernel restriction or BPF hook")
    else:
        print(f"  [INFO]  splice-to-UDP allowed — expected on pre-6.5 kernels "
              f"(sendpage path, hook is no-op)")
    skipped += 1

print()

# =====================================================================
# Sanity checks: these should always work
# =====================================================================
print("--- Sanity checks (should all be allowed) ---")

for label, fn in [
    ("AF_INET TCP",
     lambda: socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)),
    ("AF_INET UDP",
     lambda: socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)),
    ("AF_INET6 TCP",
     lambda: socket.socket(socket.AF_INET6, socket.SOCK_STREAM, 0)),
    ("AF_NETLINK (non-XFRM)",
     lambda: socket.socket(AF_NETLINK, socket.SOCK_RAW, 0)),
]:
    try:
        s = fn()
        s.close()
        check(label, True, True)
    except OSError as e:
        check(label, False, True)

print()

# =====================================================================
# Host IPsec check: NETLINK_XFRM from init namespaces
# =====================================================================
print("--- Host IPsec passthrough (NETLINK_XFRM at level 0) ---")

if in_container:
    print("  [SKIP]  Running inside a container — cannot test host-level XFRM")
    print("          Run this script via 'oc debug node/<node>' to test")
    skipped += 1
else:
    xfrm_host = try_xfrm_direct()
    check("NETLINK_XFRM from host (level 0)", xfrm_host, True)

print()

# =====================================================================
# Module status
# =====================================================================
print("--- Kernel module status ---")
try:
    with open("/proc/modules") as f:
        mods = f.read()
    for mod, desc in [
        ("esp4",  "ESP IPv4"),
        ("esp6",  "ESP IPv6"),
        ("rxrpc", "AF_RXRPC"),
    ]:
        status = "LOADED" if (mod + " ") in mods else "absent"
        print(f"  {status:8s}  {mod:6s} ({desc})")
except:
    print("  Could not read /proc/modules")

print()

# =====================================================================
# Summary
# =====================================================================
total = passed + failed + skipped
print(f"=== Summary: {passed} passed, {failed} failed, {skipped} skipped "
      f"(out of {total}) ===")

if failed > 0:
    sys.exit(1)
sys.exit(0)
