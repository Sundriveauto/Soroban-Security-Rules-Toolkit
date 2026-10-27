#!/usr/bin/env python3
"""Recall on independently reported bugs.

Each case is a public GitHub issue reporting a bug in a Soroban contract, in a
class stellar-guard targets. The repository is checked out at the pinned commit
(the default branch when the issue was filed), scanned with default settings,
and the case counts as detected when a finding of an expected rule points into
the reported file(s) and, where the issue names them, at the reported functions.

Usage:
    cargo build --release
    python3 scripts/real_bugs.py <cache dir> target/release/stellar-guard [--heldout] [--resolve]

`--resolve` prints the commit each issue was filed against instead of using the
pinned one (used once when adding a case).
"""

import json
import subprocess
import sys
from pathlib import Path

# (issue, pinned commit, rules, path filter, functions) - a finding matches when its
# file contains the path filter and (if functions are listed) its function is one of
# them. A case with several functions is detected only if every function is reported.
CASES = [
    # missing authorization
    ("RotaFi-Protocol/RotaFi#69", "f76a711", ["SG-001"], "reputation-registry/src/lib.rs",
     ["record_join", "record_completion", "record_default"]),
    ("godwinishaku506-hub/stellar-CrowdPay--Blockchain#211", "128bc07", ["SG-001"], "escrow/src/lib.rs",
     ["execute_withdrawal"]),
    # initializers anyone can call first (front-running the deployer)
    ("Sottara-Labs/sottara#348", "0837bc3", ["SG-001", "SG-005"], "postage/src/lib.rs", ["initialize"]),
    ("thisisouvik/trustlend-stellar#352", "c700570", ["SG-001", "SG-005"], "", ["initialize"]),
    ("WASTEFI-AFRICA/wastefi-contracts#55", "a460df1", ["SG-001", "SG-005"], "", ["initialize"]),
    # storage TTL never extended
    ("stellar-compliance-kit/compliance-primitives#582", "631d558", ["SG-007"], "denylist-gate", []),
    ("Kevin737866/stellar-identity-credentials-sdk#384", "8fb6167", ["SG-007"], "did_registry", []),
    ("Nodal-stellar/Nodal-AI#805", "c4009fa", ["SG-007"], "escrow/src/lib.rs", []),
    ("boluwacodes/runway#57", "c3961f2", ["SG-007"], "", []),
    # The commit the issue was filed against (ebc8f9f) is a merge that left unbalanced braces in
    # lib.rs; 77234c2 is the last earlier commit that parses and already has the reported bug.
    ("Heliobond/contracts#317", "77234c2", ["SG-007"], "investment_vault", []),
    ("stellar-zklab/stellar-zkident#291", "17ab675", ["SG-007"], "did_registry", []),
    ("StellarSend/contracts#34", "dab0fcb", ["SG-007"], "escrow/src/lib.rs", []),
    ("MeritPay/MeritPay-Contracts#14", "ec67d1e", ["SG-007"], "payroll", []),
    ("mericcintosun/alvinmunk#65", "a1c29a6", ["SG-007"], "reputation", []),
    ("stellar-gasless-net/soroban-gasless-contracts#249", "deda523", ["SG-007"], "voucher-paymaster", []),
    # unbounded iteration
    ("Kevin737866/stellar-identity-credentials-sdk#395", "8fb6167", ["SG-004"], "", ["revoke_expired_credentials"]),
    ("hartz0/scoregate-contracts#265", "7a27e88", ["SG-004"], "", ["prune_expired_parameter_proposals"]),
    ("Gospelsam019/williams-contracts#24", "2b29bbc", ["SG-004"], "", ["recompute_protocol_stats"]),
]

# Held out: collected after the rules were tuned on CASES, and scored before any
# further change. Front-running cases accept any SG-005 finding (initializer names
# vary per contract).
HELDOUT = [
    # missing authorization
    ("NativeFlow-org/nativeflow-contract#2", "15be056", ["SG-001"], "", ["execute_payment"]),
    ("Northgate-Systems/RemitX#318", "018e81d", ["SG-001"], "", ["refund"]),
    ("RevoraOrg/Revora-Contracts#1308", "51597f2", ["SG-001"], "", ["test_insert_period", "test_set_last_claimed_idx"]),
    # front-runnable initializers
    ("C-Address-Onboarding-Bridge/C-Address-Onboarding-Bridge--Contract#629", "6623651", ["SG-005"], "", []),
    ("ExcelDsigN-tech/DukaPay#757", "cf23338", ["SG-005"], "", []),
    ("Godgift-care/sci-healthcare-contracts#87", "7d24c2b", ["SG-005"], "", []),
    ("Goldii-locks/escrow-contract#665", "1884c5c", ["SG-005"], "milestone-escrow", []),
    ("Hamplard-Hub/Hamplard--contracts#421", "cb09329", ["SG-005"], "", []),
    ("Haroldwonder/AnchorKit#1346", "d643e0e", ["SG-005"], "", []),
    ("Lead-Studios/veritix-contract#1080", "e53f2ea", ["SG-005"], "", []),
    ("Sylox-labs/sylox#21", "47ce27d", ["SG-005"], "", []),
    ("SorobanCrashLab/soroban-crashlab#1549", "360db3b", ["SG-005"], "soroban-example", []),
    ("Rickyy1017/Stellar-Defi-Vault#737", "5fa0b75", ["SG-005"], "", []),
    # storage TTL
    ("Galaxy-KJ/Galaxy-DevKit#384", "c11266e", ["SG-007"], "packages/contracts", []),
    ("OpenLedger-Foundation/Kora-Contract#356", "cbf17fa", ["SG-007"], "marketplace", []),
    ("Ajo-contrib/soroban-ajo#856", "6cc1d5b", ["SG-007"], "", []),
    # unbounded iteration
    ("Gloriachinedu/lumenflow-contracts#1313", "2d8ac23", ["SG-004"], "", ["cleanup_expired_payments"]),
    ("SoroStream/sorostream-contracts#727", "f652ee5", ["SG-004"], "", ["compute_cumulative_decay"]),
    ("Receiptaa/Receipta#47", "8ee8b24", ["SG-004"], "", ["get_receipts_by_receiver"]),
    # Navin-xmr/navin-contracts#987 is excluded: the O(n) loop it reports in `balance_of` does not
    # exist anywhere in the history of contracts/nft/src/lib.rs.
    ("benelabs/crucible#1105", "55d6d93", ["SG-004"], "quadratic-funding", ["claim_payout"]),
    ("Tx-wat/stellar-txwatch-contracts#209", "673e870", ["SG-004"], "", ["configs_paginated"]),
]


def run(*args, cwd=None):
    return subprocess.run(args, cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


def checkout(cache: Path, issue: str, pinned: str, resolve: bool) -> tuple[Path, str]:
    repo, number = issue.split("#")
    dest = cache / repo.replace("/", "__")
    if not dest.exists():
        run("git", "clone", "-q", "--filter=blob:none", f"https://github.com/{repo}", str(dest))
    commit = pinned
    if resolve or not commit:
        created = json.loads(run("gh", "api", f"repos/{repo}/issues/{number}"))["created_at"]
        commit = run("git", "rev-list", "-1", f"--before={created}", "HEAD", cwd=dest)
    run("git", "checkout", "-q", "--force", commit, cwd=dest)
    return dest, commit


def scan(binary: str, path: Path) -> list[dict]:
    out = subprocess.run(
        [binary, "scan", str(path), "--no-config", "--format", "json", "--fail-on", "never", "-q"],
        capture_output=True, text=True,
    )
    if out.returncode != 0:
        return []
    return json.loads(out.stdout)["findings"]


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    cache, binary = Path(sys.argv[1]), sys.argv[2]
    resolve = "--resolve" in sys.argv
    cases = HELDOUT if "--heldout" in sys.argv else CASES
    cache.mkdir(parents=True, exist_ok=True)
    detected = 0
    for issue, pinned, rules, path_filter, functions in cases:
        dest, commit = checkout(cache, issue, pinned, resolve)
        hits = [
            f for f in scan(binary, dest)
            if f["rule_id"] in rules and path_filter in f["location"]["file"].replace("\\", "/")
        ]
        if functions:
            found = {f["function"] for f in hits if f["function"] in functions}
            ok = found == set(functions)
            detail = f"{len(found)}/{len(functions)} functions"
        else:
            ok = bool(hits)
            detail = f"{len(hits)} findings"
        severities = sorted({f["severity"] for f in hits})
        detected += ok
        status = "DETECTED" if ok else "MISSED  "
        print(f"{status}  {issue}  @{commit[:7]}  {'/'.join(rules)}: {detail} {severities}")
    print(f"\n{detected}/{len(cases)} reported bugs detected")
    return 0


if __name__ == "__main__":
    sys.exit(main())
