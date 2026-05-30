"""
Project 4 — Password Audit & Cracking Tool
Generates a synthetic hash dump then attempts to crack it.
Dependencies: pip install passlib[bcrypt] tqdm
Usage: python auditor.py --wordlist rockyou.txt
"""

import argparse, hashlib, json, time
from pathlib import Path
from tqdm import tqdm
from passlib.hash import bcrypt as bcrypt_hash

# ── Hash helpers ─────────────────────────────────────────
def md5(p: str)    -> str: return hashlib.md5(p.encode()).hexdigest()
def sha1(p: str)   -> str: return hashlib.sha1(p.encode()).hexdigest()
def sha256(p: str) -> str: return hashlib.sha256(p.encode()).hexdigest()

HASH_FNS = {"md5": md5, "sha1": sha1, "sha256": sha256}

WEAK_PASSWORDS = [
    "password", "123456", "admin", "letmein", "qwerty",
    "password1", "iloveyou", "sunshine", "princess", "welcome"
]

# ── Mangling rules ────────────────────────────────────────
def mangle(word: str):
    yield word
    yield word.capitalize()
    yield word.upper()
    yield word + "1"
    yield word + "123"
    yield word + "!"
    yield word.replace("a", "@").replace("e", "3").replace("o", "0")


# ── Generate synthetic dump ───────────────────────────────
def generate_dump(path: str = "dump.txt") -> str:
    entries = []
    for pw in WEAK_PASSWORDS:
        entries.append(f"user_md5_{pw}:md5:{md5(pw)}")
        entries.append(f"user_sha1_{pw}:sha1:{sha1(pw)}")
    for pw in ["hunter2", "correct-horse"]:
        entries.append(f"admin_{pw}:bcrypt:{bcrypt_hash.hash(pw)}")
    Path(path).write_text("\n".join(entries))
    print(f"[*] Synthetic dump → {path}  ({len(entries)} accounts)")
    return path


# ── Crack one hash ────────────────────────────────────────
def crack_hash(algo: str, target: str, wordlist_path: str) -> str | None:
    if algo == "bcrypt":
        return None   # GPU-based tool (Hashcat) recommended for bcrypt

    fn = HASH_FNS.get(algo)
    if not fn:
        return None

    with open(wordlist_path, encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            for variant in mangle(line.strip()):
                if fn(variant) == target:
                    return variant
    return None


# ── Main audit ────────────────────────────────────────────
def audit(dump_path: str, wordlist_path: str) -> None:
    lines   = Path(dump_path).read_text().splitlines()
    results = []
    cracked = 0
    t0      = time.time()

    for line in tqdm(lines, desc="Cracking"):
        parts = line.split(":")
        if len(parts) < 3:
            continue
        username, algo, hsh = parts[0], parts[1], parts[2]
        password = crack_hash(algo, hsh, wordlist_path)
        if password:
            cracked += 1
        results.append({
            "username": username,
            "algo":     algo,
            "cracked":  password is not None,
            "password": password or "—"
        })

    elapsed = time.time() - t0
    pct     = round(cracked / len(results) * 100, 1) if results else 0
    report  = {
        "total":       len(results),
        "cracked":     cracked,
        "pct_cracked": pct,
        "elapsed_s":   round(elapsed, 2),
        "accounts":    results
    }

    out = "audit_report.json"
    with open(out, "w") as fh:
        json.dump(report, fh, indent=2)

    print(f"\n{'='*45}")
    print(f" Total accounts : {report['total']}")
    print(f" Cracked        : {report['cracked']} ({report['pct_cracked']}%)")
    print(f" Time taken     : {report['elapsed_s']}s")
    print(f" Report saved   : {out}")
    print(f"{'='*45}")
    print(" ⚠  Recommendation: replace MD5/SHA-1 with bcrypt or argon2id\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Password Auditor")
    parser.add_argument("--wordlist", default="wordlist.txt")
    parser.add_argument("--dump",     default="",
                        help="Existing dump file (leave blank to auto-generate)")
    args = parser.parse_args()

    wl = args.wordlist
    if not Path(wl).exists():
        Path(wl).write_text("\n".join(
            WEAK_PASSWORDS + ["hunter2", "correct-horse", "monkey", "dragon"]))
        print(f"[*] No wordlist found — wrote built-in list to {wl}")

    dump = args.dump if args.dump else generate_dump()
    audit(dump, wl)
