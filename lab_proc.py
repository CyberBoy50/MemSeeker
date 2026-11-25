#!/usr/bin/env python3
"""MemSeeker lab process — holds planted markers in memory, then sleeps.

Run it, note its PID, and scan it with MemSeeker. It prints ONE JSON
line on stdout with its PID and the address of every marker, then
sleeps until killed (Ctrl+C or `kill <pid>`).

WHY THE MARKERS ARE BUILT THIS WAY — read this before changing them:
  If a marker string appeared literally in this file (writing the
  whole marker as one bytes literal), the Python interpreter would
  keep that literal in memory as a code constant — and the source file
  itself is mapped into memory too. The marker would then match in
  MORE than one place, and the tests could not say which region the
  hit came from. So every marker is built at RUNTIME (joining short
  parts, or bytes from ints, or os.urandom) — the full marker bytes
  never appear anywhere in this file. The tests assert each hit is in
  the anonymous heap region, where the marker buffer lives.

Markers (all kept in module globals so they stay alive):
  alpha     — plain string,  rule MemMarkerAlpha
  password  — leaked password string, rule LeakedPassword
  hex       — byte sequence,  rule InjectedBytes
  apikey    — regex-shaped key, rule ApiKeyPattern
  straddle  — plain string,  rule StraddleMarker (Step 5 boundary test)
  entropy   — 256 KiB of random bytes (entropy scan target)
  decoy_beta / decoy_short — look-alikes that must NOT match any rule
"""
import ctypes
import json
import os
import sys
import time

# --- Planted markers (built at runtime — see the note above) ----------
MARKER_ALPHA = bytearray(b"".join([b"MEMSEEKER_", b"MARKER_", b"ALPHA"]))
MARKER_PASSWORD = bytearray(b"".join([b"hunter", b"2"]))
MARKER_HEX = bytearray(bytes([0xDE, 0xAD, 0xBE, 0xEF,
                              0x00, 0x11, 0x22, 0x33]))
MARKER_APIKEY = bytearray(b"".join([b"sk-", b"ABCDEFGH",
                                   b"12345678", b"XYZABCDE"]))
MARKER_STRADDLE = bytearray(b"".join([b"MEMSEEKER_", b"STRADDLE_",
                                      b"MARKER"]))
# 256 KiB of random bytes: several whole 64 KiB chunks of it are pure
# random data, so the entropy scan flags them (~8.0 bits/byte).
BLOB_ENTROPY = bytearray(os.urandom(256 * 1024))
# Decoys: similar-looking, must NOT match any rule.
DECOY_BETA = bytearray(b"".join([b"MEMSEEKER_", b"MARKER_", b"BETA"]))
DECOY_SHORT = bytearray(b"".join([b"sk-", b"ABCDEF", b"1234"]))


def buffer_address(buf):
    """Absolute address of a bytearray's data buffer."""
    return ctypes.addressof(ctypes.c_char.from_buffer(buf))


def main():
    markers = {
        "alpha": buffer_address(MARKER_ALPHA),
        "password": buffer_address(MARKER_PASSWORD),
        "hex": buffer_address(MARKER_HEX),
        "apikey": buffer_address(MARKER_APIKEY),
        "straddle": buffer_address(MARKER_STRADDLE),
        "entropy_blob": buffer_address(BLOB_ENTROPY),
        "decoy_beta": buffer_address(DECOY_BETA),
        "decoy_short": buffer_address(DECOY_SHORT),
    }
    print(json.dumps({"pid": os.getpid(), "markers": markers}),
          flush=True)
    # Sleep until killed. Nothing else allocates after this point, so
    # the marker addresses stay valid for the whole scan.
    try:
        for _ in range(60):
            time.sleep(60)
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
