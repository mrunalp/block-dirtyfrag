#!/usr/bin/env python3
"""Trigger AF_RXRPC and XFRM operations to test the blocker."""
import socket
import os

AF_RXRPC = 33

tests = [
    ("AF_RXRPC socket", lambda: socket.socket(AF_RXRPC, socket.SOCK_DGRAM, socket.AF_INET)),
    ("AF_INET TCP",     lambda: socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)),
    ("AF_INET UDP",     lambda: socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)),
    ("AF_ALG skcipher", lambda: _alg_bind("skcipher", "cbc(aes)")),
]

def _alg_bind(alg_type, alg_name):
    s = socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)
    s.bind((alg_type, alg_name))
    return s

for label, fn in tests:
    try:
        s = fn()
        print(f"ALLOWED: {label}")
        s.close()
    except OSError as e:
        print(f"BLOCKED: {label} — {e}")
