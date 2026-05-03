import os
import subprocess
import threading
from collections import defaultdict

ciphertext_store = defaultdict(list)
recovery_lock = threading.Lock()
recovery_in_progress = False

def store_ciphertext(tgid, kid, ciphertext_bytes):
    """Store ciphertext for key recovery (called from p25_frame.py)."""
    ciphertext_hex = ciphertext_bytes.hex().upper()
    with recovery_lock:
        ciphertext_store[(tgid, kid)].append(ciphertext_hex)
        if len(ciphertext_store[(tgid, kid)]) > 5:
            ciphertext_store[(tgid, kid)] = ciphertext_store[(tgid, kid)][-5:]

def recover_key(ciphertext_hex, cipher_type="adp"):
    """Call C++ tool to recover key. Returns key_hex or None."""
    global recovery_in_progress
    if recovery_in_progress:
        return None
    recovery_in_progress = True
    try:
        binary_paths = [
            "./tools/p25_keyextractor/p25_keyextractor",
            "./tools/p25_keyextractor/build/p25_keyextractor",
            "./tools/p25_keyextractor/build/Release/p25_keyextractor.exe",
            "p25_keyextractor"
        ]
        for binary in binary_paths:
            if os.path.exists(binary):
                cmd = [binary, ciphertext_hex, cipher_type]
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=3600
                )
                if result.returncode == 0 and result.stdout.startswith("0x"):
                    return result.stdout.strip()
        return None
    except Exception as e:
        print(f"[!] Key recovery error: {e}")
        return None
    finally:
        recovery_in_progress = False

def attempt_recovery(tgid=None, kid=None):
    """Attempt recovery for all or specific (tgid, kid)."""
    results = []
    with recovery_lock:
        targets = [(tgid, kid)] if (tgid is not None and kid is not None) else list(ciphertext_store.keys())
        for (tgid, kid) in targets:
            samples = ciphertext_store.get((tgid, kid), [])
            if not samples:
                continue
            ciphertext_hex = samples[0]
            print(f"[*] Attempting {cipher_type} recovery for TGID {tgid}, KID {kid:#x}...")
            key = recover_key(ciphertext_hex, "adp")
            if key:
                results.append((tgid, kid, "ADP", key))
                ciphertext_store[(tgid, kid)] = []
    return results

def add_recovered_key(kid, key_type, key_hex):
    """Append key to OP25's keys.txt file."""
    key_file = "keys.txt"
    with open(key_file, "a") as f:
        f.write(f"{kid:#x},{key_type},{key_hex}\n")
    print(f"[+] Added key {kid:#x} ({key_type}) to {key_file}")