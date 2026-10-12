#!/usr/bin/env python3
# Copyright (c) 2026 The fips205-slhdsa-esp32 authors
# SPDX-License-Identifier: Apache-2.0
"""
Generate a C header with NIST ACVP SLH-DSA (FIPS 205) test vectors.

The vectors come from the official NIST ACVP server repository:
  https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files
    SLH-DSA-keyGen-FIPS205/{prompt,expectedResults}.json
    SLH-DSA-sigGen-FIPS205/{prompt,expectedResults}.json
    SLH-DSA-sigVer-FIPS205/{prompt,expectedResults}.json

SLH-DSA signatures are large (7.8-49.9 KB), so byte strings are emitted as
binary string literals ("\\x12\\x34...", one byte of flash per byte) together
with their lengths, and expected sigGen signatures are replaced by their
SHA-256 digest.

Every sigGen / sigVer case is mapped to one of three modes:
  MODE_PURE      external interface, pure SLH-DSA (message + context)
  MODE_PREHASH   external interface, HashSLH-DSA (the device hashes the
                 message itself with the named hash function)
  MODE_INTERNAL  internal interface (slh_sign_internal / slh_verify_internal)

By default a subset is emitted that runs in a few minutes on an ESP32: per
parameter set --keygen keyGen and --sigver sigVer cases, and --siggen sigGen
cases for the fast ("f") sets. The small-signature ("s") sets sign slowly
on an ESP32 (about a minute for SHA2-128s, many minutes for the larger
ones), so they get --siggen-s sigGen cases, and only the sets listed in
--siggen-s-sets. Cases cycle through the modes and the deterministic/hedged
variants, preferring short messages. --all emits every case (host tests).

Usage:
  scripts/gen_acvp_vectors.py --download --out examples/slhdsa_test_vectors/acvp_vectors.h
  scripts/gen_acvp_vectors.py --acvp-dir DIR --all --out acvp_all.h
"""

import argparse
import hashlib
import json
import sys
import urllib.request
from pathlib import Path

RAW_BASE = ("https://raw.githubusercontent.com/usnistgov/ACVP-Server/"
            "{ref}/gen-val/json-files/")
NAMES = ["SLH-DSA-keyGen-FIPS205", "SLH-DSA-sigGen-FIPS205", "SLH-DSA-sigVer-FIPS205"]
# Order matches the slhdsa_esp32 parameter set index used by the runner.
SETS = ["SLH-DSA-SHA2-128s", "SLH-DSA-SHAKE-128s", "SLH-DSA-SHA2-128f", "SLH-DSA-SHAKE-128f",
        "SLH-DSA-SHA2-192s", "SLH-DSA-SHAKE-192s", "SLH-DSA-SHA2-192f", "SLH-DSA-SHAKE-192f",
        "SLH-DSA-SHA2-256s", "SLH-DSA-SHAKE-256s", "SLH-DSA-SHA2-256f", "SLH-DSA-SHAKE-256f"]


def download(acvp_dir: Path, ref: str) -> None:
    for name in NAMES:
        for f in ("prompt.json", "expectedResults.json"):
            dst = acvp_dir / name / f
            if dst.exists():
                continue
            dst.parent.mkdir(parents=True, exist_ok=True)
            url = RAW_BASE.format(ref=ref) + f"{name}/{f}"
            print(f"downloading {url}", file=sys.stderr)
            with urllib.request.urlopen(url, timeout=300) as r:
                dst.write_bytes(r.read())


def load(acvp_dir: Path, name: str):
    prompt = json.loads((acvp_dir / name / "prompt.json").read_text())
    expected = json.loads((acvp_dir / name / "expectedResults.json").read_text())
    exp = {t["tcId"]: t for g in expected["testGroups"] for t in g["tests"]}
    return prompt, exp


def blob(h):
    """C expression (pointer, length) for a hex string; NULL for None."""
    if h is None:
        return ["NULL", "0"]
    b = bytes.fromhex(h)
    lit = "".join(f"\\x{x:02x}" for x in b)
    return [f'(const uint8_t *)"{lit}"', str(len(b))]


def sha256_blob(h):
    return blob(hashlib.sha256(bytes.fromhex(h)).hexdigest())


def mode_of(group):
    if group["signatureInterface"] == "internal":
        return "MODE_INTERNAL"
    return "MODE_PREHASH" if group["preHash"] == "preHash" else "MODE_PURE"


def msg_len(t):
    return len(t.get("message", "")) + len(t.get("context", ""))


def pick(groups, n, valid_of=None, per_set=None):
    """Up to n cases per parameter set (per_set(ps) overrides n), round-robin
    over its groups (i.e. over modes / variants), shortest messages first;
    for sigVer alternate between valid and invalid signatures."""
    if n is None:
        return [(g, t) for g in groups for t in g["tests"]]
    out = []
    for ps in SETS:
        n_ps = n if per_set is None else per_set(ps)
        pools = []
        for g in (g for g in groups if g["parameterSet"] == ps):
            tests = sorted(g["tests"], key=msg_len)
            if valid_of is not None:
                good = [t for t in tests if valid_of(t)]
                bad = [t for t in tests if not valid_of(t)]
                tests = [x for pair in zip(good, bad) for x in pair] + good[len(bad):] + bad[len(good):]
            pools.append((g, tests))
        # rotate the starting group per parameter set, so that the subset
        # covers all modes / variants across the parameter sets
        if pools:
            r = SETS.index(ps) % len(pools)
            pools = pools[r:] + pools[:r]
        chosen = []
        while len(chosen) < n_ps and any(p[1] for p in pools):
            for g, tests in pools:
                if tests and len(chosen) < n_ps:
                    chosen.append((g, tests.pop(0)))
        if valid_of is not None and n_ps >= 2 and chosen and \
                len({valid_of(t) for _, t in chosen}) == 1:
            # make sure both outcomes are represented
            want = not valid_of(chosen[0][1])
            last_g = chosen[-1][0]
            for g, tests in sorted(pools, key=lambda p: p[0] is not last_g):
                alt = [t for t in tests if valid_of(t) == want]
                if alt:
                    chosen[-1] = (g, alt[0])
                    break
        out += chosen
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--acvp-dir", type=Path, default=Path(".acvp-data"))
    ap.add_argument("--download", action="store_true",
                    help="fetch missing JSON files from GitHub first")
    ap.add_argument("--ref", default="master", help="ACVP-Server git ref")
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--keygen", type=int, default=1, help="keyGen cases per parameter set")
    ap.add_argument("--siggen", type=int, default=2, help="sigGen cases per fast (f) set")
    ap.add_argument("--siggen-s", type=int, default=1, help="sigGen cases per slow (s) set")
    ap.add_argument("--siggen-s-sets", default="0",
                    help="comma-separated indices of the s sets that get --siggen-s cases")
    ap.add_argument("--sigver", type=int, default=2, help="sigVer cases per parameter set")
    ap.add_argument("--sets", default=None,
                    help="comma-separated parameter set indices (0-11) to include")
    ap.add_argument("--all", action="store_true", help="include every test case")
    a = ap.parse_args()
    if a.all:
        a.keygen = a.siggen = a.sigver = None
    if a.download:
        download(a.acvp_dir, a.ref)
    only = None if a.sets is None else {SETS[int(i)] for i in a.sets.split(",")}

    kg_p, kg_e = load(a.acvp_dir, NAMES[0])
    sg_p, sg_e = load(a.acvp_dir, NAMES[1])
    sv_p, sv_e = load(a.acvp_dir, NAMES[2])

    def keep(g):
        return only is None or g["parameterSet"] in only

    kg_rows, sg_rows, sv_rows = [], [], []
    for g, t in pick([g for g in kg_p["testGroups"] if keep(g)], a.keygen):
        seed = t["skSeed"] + t["skPrf"] + t["pkSeed"]
        kg_rows.append([str(t["tcId"]), str(SETS.index(g["parameterSet"]))] + blob(seed)
                       + blob(kg_e[t["tcId"]]["sk"]))
    s_sets = {SETS[int(i)] for i in a.siggen_s_sets.split(",") if i != ""}
    siggen_n = None if a.siggen is None else (
        lambda ps: a.siggen if ps.endswith("f") else (a.siggen_s if ps in s_sets else 0))
    for g, t in pick([g for g in sg_p["testGroups"] if keep(g)], a.siggen, per_set=siggen_n):
        mode = mode_of(g)
        ha = f'"{t["hashAlg"]}"' if mode == "MODE_PREHASH" else "NULL"
        rnd = None if g["deterministic"] else t["additionalRandomness"]
        ctx = t.get("context") if mode != "MODE_INTERNAL" else None
        sg_rows.append([str(t["tcId"]), str(SETS.index(g["parameterSet"])), mode, ha]
                       + blob(t["sk"]) + blob(t["message"]) + blob(ctx) + blob(rnd)
                       + sha256_blob(sg_e[t["tcId"]]["signature"]))
    valid = lambda t: sv_e[t["tcId"]]["testPassed"]
    for g, t in pick([g for g in sv_p["testGroups"] if keep(g)], a.sigver, valid):
        mode = mode_of(g)
        ha = f'"{t["hashAlg"]}"' if mode == "MODE_PREHASH" else "NULL"
        ctx = t.get("context") if mode != "MODE_INTERNAL" else None
        sv_rows.append([str(t["tcId"]), str(SETS.index(g["parameterSet"])), mode, ha]
                       + blob(t["pk"]) + blob(t["message"]) + blob(ctx) + blob(t["signature"])
                       + ["true" if valid(t) else "false"])

    L = ["/*",
         " * NIST ACVP SLH-DSA (FIPS 205) test vectors -- AUTO-GENERATED, do not edit.",
         " *",
         " * Generator: scripts/gen_acvp_vectors.py" + (" --all" if a.all else ""),
         " * Source:    https://github.com/usnistgov/ACVP-Server (gen-val/json-files)",
         f" *            SLH-DSA-keyGen-FIPS205 vsId={kg_p.get('vsId')}, "
         f"SLH-DSA-sigGen-FIPS205 vsId={sg_p.get('vsId')}, "
         f"SLH-DSA-sigVer-FIPS205 vsId={sv_p.get('vsId')}",
         " *",
         " * set = parameter set index: " + ", ".join(f"{i}={s[8:]}" for i, s in enumerate(SETS[:6])) + ",",
         " *       " + ", ".join(f"{i + 6}={s[8:]}" for i, s in enumerate(SETS[6:])) + ".",
         " * rnd == NULL marks the deterministic variant; sig_sha256 is the SHA-256",
         " * digest of the expected signature.",
         " */",
         "",
         "#ifndef ACVP_VECTORS_H",
         "#define ACVP_VECTORS_H",
         "",
         "#include <stdbool.h>",
         "#include <stddef.h>",
         "#include <stdint.h>",
         "",
         "enum acvp_mode { MODE_PURE, MODE_PREHASH, MODE_INTERNAL };",
         "",
         "typedef struct {",
         "  uint16_t tcId; uint8_t set;",
         "  const uint8_t *seed; size_t seed_len;  /* SK.seed || SK.prf || PK.seed */",
         "  const uint8_t *sk; size_t sk_len;      /* expected secret key (contains pk) */",
         "} acvp_keygen_t;",
         "typedef struct {",
         "  uint16_t tcId; uint8_t set; uint8_t mode; const char *hashAlg;",
         "  const uint8_t *sk; size_t sk_len;",
         "  const uint8_t *msg; size_t msg_len;",
         "  const uint8_t *ctx; size_t ctx_len;",
         "  const uint8_t *rnd; size_t rnd_len;",
         "  const uint8_t *sig_sha256; size_t sig_sha256_len;",
         "} acvp_siggen_t;",
         "typedef struct {",
         "  uint16_t tcId; uint8_t set; uint8_t mode; const char *hashAlg;",
         "  const uint8_t *pk; size_t pk_len;",
         "  const uint8_t *msg; size_t msg_len;",
         "  const uint8_t *ctx; size_t ctx_len;",
         "  const uint8_t *sig; size_t sig_len;",
         "  bool valid;",
         "} acvp_sigver_t;",
         ""]
    for kind, ctype, rows in (("keygen", "acvp_keygen_t", kg_rows),
                              ("siggen", "acvp_siggen_t", sg_rows),
                              ("sigver", "acvp_sigver_t", sv_rows)):
        L.append(f"static const {ctype} acvp_{kind}[] = {{")
        L += ["  {" + ", ".join(r) + "}," for r in rows]
        L += ["};", f"static const size_t acvp_{kind}_count = {len(rows)};", ""]
    L.append("#endif /* ACVP_VECTORS_H */")
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text("\n".join(L) + "\n")
    print(f"keygen={len(kg_rows)} siggen={len(sg_rows)} sigver={len(sv_rows)}", file=sys.stderr)
    print(f"wrote {a.out} ({a.out.stat().st_size} bytes)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
