#!/usr/bin/env python3
"""Recall check: seed one known bug at a time into stellar/soroban-examples and
report whether stellar-guard finds something new.

Usage:
    git clone https://github.com/stellar/soroban-examples /tmp/se
    git -C /tmp/se checkout 03d42aa
    cargo build --release
    python3 scripts/seeded_bugs.py /tmp/se target/release/stellar-guard

Each case edits one line of a copy of an example crate. A case counts as
detected when the mutated copy has a finding (rule + message) that the
unmodified crate does not. Results are documented in docs/validation.md.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile

# (title, crate dir, file, 1-based line, old text, replacement)
CASES = [
    ("token: transfer_from without spend_allowance", "token", "src/contract.rs", 150,
     "spend_allowance(&e, from.clone(), spender, amount);", ""),
    ("token: transfer without from.require_auth()", "token", "src/contract.rs", 121, "from.require_auth();", ""),
    ("token: mint without check_nonnegative_amount", "token", "src/contract.rs", 53,
     "check_nonnegative_amount(amount);", ""),
    ("token: transfer auth only when amount > 0", "token", "src/contract.rs", 121, "from.require_auth();",
     "if amount > 0 { from.require_auth(); }"),
    ("token: transfer auth inside an unused closure", "token", "src/contract.rs", 121, "from.require_auth();",
     "let _f = || from.require_auth();"),
    ("token: set_admin without admin.require_auth()", "token", "src/contract.rs", 67, "admin.require_auth();", ""),
    ("token: balances in temporary storage", "token", "src/balance.rs", 18, "persistent()", "temporary()"),
    ("simple_account: __check_auth without ed25519_verify", "simple_account", "src/lib.rs", 60,
     "env.crypto()", "let _ = (&public_key, &signature, &signature_payload); env.crypto()"),
    ("liquidity_pool: withdraw without to.require_auth()", "liquidity_pool", "src/lib.rs", 304,
     "to.require_auth();", ""),
    ("single_offer: withdraw without seller auth", "single_offer", "src/lib.rs", 131,
     "offer.seller.require_auth();", ""),
    ("timelock: claim without claimant auth", "timelock", "src/lib.rs", 96, "claimant.require_auth();", ""),
    ("upgradeable_contract: upgrade without admin auth", "upgradeable_contract/old_contract", "src/lib.rs", 26,
     "admin.require_auth();", ""),
]


def scan(binary, path, out):
    subprocess.run([binary, "scan", path, "--no-config", "--format", "json", "-o", out, "--fail-on", "never", "-q"],
                   check=True, capture_output=True)
    return {(f["rule_id"], f["message"]) for f in json.load(open(out))["findings"]}


def main():
    examples, binary = sys.argv[1], os.path.abspath(sys.argv[2])
    work = tempfile.mkdtemp()
    out = os.path.join(work, "report.json")
    detected = 0
    for title, crate, rel, line, old, new in CASES:
        src = os.path.join(examples, crate)
        dst = os.path.join(work, "mut", crate)
        shutil.rmtree(os.path.join(work, "mut"), ignore_errors=True)
        shutil.copytree(src, dst)
        path = os.path.join(dst, rel)
        lines = open(path).read().split("\n")
        if old not in lines[line - 1]:
            sys.exit(f"{title}: line {line} of {crate}/{rel} does not contain {old!r}; wrong commit?")
        if new.startswith("let _ = (&public_key"):
            # Drop the whole `env.crypto().ed25519_verify(..);` statement.
            text = "\n".join(lines)
            start = text.index("env.crypto()", sum(len(l) + 1 for l in lines[: line - 1]))
            end = text.index(";", start) + 1
            text = text[:start] + new.replace(" env.crypto()", "") + text[end:]
        else:
            lines[line - 1] = lines[line - 1].replace(old, new)
            text = "\n".join(lines)
        open(path, "w").write(text)
        added = sorted(scan(binary, dst, out) - scan(binary, src, out))
        detected += bool(added)
        print(f"{'DETECTED' if added else 'missed  '}  {title}")
        for rule, message in added:
            print(f"            {rule}: {message}")
    print(f"\n{detected}/{len(CASES)} seeded bugs detected")
    shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
