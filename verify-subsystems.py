#!/usr/bin/env python3
"""Verify that AF_RXRPC sockets are blocked while other subsystems work."""
import socket

AF_RXRPC = 33

tests = [
    ("AF_RXRPC SOCK_DGRAM",  AF_RXRPC,         socket.SOCK_DGRAM,     socket.AF_INET),
    ("AF_INET TCP",           socket.AF_INET,   socket.SOCK_STREAM,    0),
    ("AF_INET UDP",           socket.AF_INET,   socket.SOCK_DGRAM,     0),
    ("AF_INET6 TCP",          socket.AF_INET6,  socket.SOCK_STREAM,    0),
    ("AF_UNIX STREAM",        socket.AF_UNIX,   socket.SOCK_STREAM,    0),
    ("AF_NETLINK RAW",        socket.AF_NETLINK, socket.SOCK_RAW,      0),
]

for label, family, stype, proto in tests:
    try:
        s = socket.socket(family, stype, proto)
        print(f"  ALLOWED  {label}")
        s.close()
    except OSError as e:
        print(f"  BLOCKED  {label} — {e}")

print()
print("AF_ALG subsystem tests:")
alg_tests = [
    ("hash",     "sha256"),
    ("skcipher", "cbc(aes)"),
    ("aead",     "gcm(aes)"),
]
for alg_type, alg_name in alg_tests:
    try:
        s = socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)
        s.bind((alg_type, alg_name))
        print(f"  ALLOWED  AF_ALG {alg_type}/{alg_name}")
        s.close()
    except OSError as e:
        print(f"  BLOCKED  AF_ALG {alg_type}/{alg_name} — {e}")
