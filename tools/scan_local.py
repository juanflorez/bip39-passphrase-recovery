#!/usr/bin/env python3
"""Identify which candidate xpub owns coins, using YOUR OWN Bitcoin Core node.

Takes the CSV produced by derive_xpubs.py (on the air-gapped machine),
expands every xpub into receive + change descriptors for its script type,
and runs ONE scantxoutset over the UTXO set. scantxoutset works on a pruned
node and queries nothing outside this host — no public servers, no explorers,
so it leaks none of your wallet's addresses. This is the private way to scan.

Run it against a fully-synced node (a scan of a half-synced UTXO set proves
nothing — the coins may simply not exist yet at that height; the script
refuses to run while the node is still in initial block download):

    python3 scan_local.py xpubs.csv
    python3 scan_local.py xpubs.csv --cli "bitcoin-cli -datadir=/path/to/data"

By default it invokes a plain `bitcoin-cli` on the local host; pass --cli to
point at a custom binary, datadir, conf file, or `sudo -u <user>` wrapper.

Caveats:
  - Only finds UNSPENT coins (it scans the UTXO set, not history).
  - The scan iterates the whole UTXO set; expect a few minutes.
  - Default address range per chain is 0..200; raise --range if the old
    wallet may have used more addresses than that.
"""

import argparse
import csv
import json
import subprocess
import sys

# Plain local bitcoin-cli. Override with --cli for a custom datadir/conf or a
# `sudo -u bitcoin bitcoin-cli ...` wrapper on a multi-user host.
DEFAULT_CLI = "bitcoin-cli -rpcclienttimeout=0"

DESC_TEMPLATES = {
    44: "pkh({x}/{c}/*)",
    49: "sh(wpkh({x}/{c}/*))",
    84: "wpkh({x}/{c}/*)",
    86: "tr({x}/{c}/*)",
}


def cli(cli_prefix, *args, stdin_args=None):
    # With many descriptors the scantxoutset JSON blows past ARG_MAX as a
    # single argv entry, so pass those args via bitcoin-cli -stdin (one
    # argument per line, taken literally — no shell re-parsing).
    if stdin_args is not None:
        res = subprocess.run(cli_prefix.split() + ["-stdin"],
                             input="\n".join(stdin_args),
                             capture_output=True, text=True)
    else:
        res = subprocess.run(cli_prefix.split() + list(args),
                             capture_output=True, text=True)
    if res.returncode != 0:
        sys.exit(f"bitcoin-cli failed: {res.stderr.strip()}")
    return res.stdout.strip()


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("csv_file", help="xpubs.csv from derive_xpubs.py")
    ap.add_argument("--range", type=int, default=200,
                    help="address index range per chain (default 200)")
    ap.add_argument("--cli", default=DEFAULT_CLI,
                    help="bitcoin-cli invocation prefix")
    args = ap.parse_args()

    info = json.loads(cli(args.cli, "getblockchaininfo"))
    if info["initialblockdownload"]:
        sys.exit(f"Node is still in IBD ({info['verificationprogress']:.1%}) — "
                 "a UTXO scan now would be meaningless. Wait for sync to finish.")

    rows = []
    with open(args.csv_file, newline="") as f:
        for row in csv.DictReader(f):
            rows.append((int(row["candidate"]), int(row["purpose"]),
                         int(row["account"]), row["xpub"]))
    if not rows:
        sys.exit("no xpubs in CSV")

    xpub_map = {x: (cand, purpose, account) for cand, purpose, account, x in rows}
    scanobjects = []
    for _, purpose, _, xpub in rows:
        for chain in (0, 1):  # receive + change
            scanobjects.append({
                "desc": DESC_TEMPLATES[purpose].format(x=xpub, c=chain),
                "range": args.range,
            })

    n_cands = len({c for c, _, _, _ in rows})
    print(f"Scanning UTXO set at height {info['blocks']} for "
          f"{len(scanobjects)} descriptors ({n_cands} candidates) — this takes minutes...")
    result = json.loads(cli(args.cli, stdin_args=["scantxoutset", "start",
                                                  json.dumps(scanobjects)]))

    if not result.get("success"):
        sys.exit("scan did not complete successfully")
    totals = {}
    for u in result.get("unspents", []):
        owner = next((xpub_map[x] for x in xpub_map if x in u["desc"]), None)
        if owner is None:
            print(f"warning: could not map unspent to a candidate: {u['desc']}")
            continue
        key = owner
        totals.setdefault(key, [0.0, 0])
        totals[key][0] += float(u["amount"])
        totals[key][1] += 1

    print(f"\nScan complete (height {result['height']}, "
          f"total found: {result.get('total_amount', 0)} BTC)\n")
    if not totals:
        print("NO MATCHES. Possible reasons: passphrase not in the candidate list")
        print("(check spacing/capitalization variants), wallet used an account or")
        print("address index beyond the derived/scanned range, or the coins were spent.")
        return
    for (cand, purpose, account), (amount, n) in sorted(totals.items()):
        print(f"  candidate line #{cand}  ->  {amount:.8f} BTC in {n} UTXO(s) "
              f"at m/{purpose}'/0'/{account}'")
    print("\n'candidate line #N' = line N (1-based) of your candidates file.")
    print("Confirm by entering that passphrase on the device and checking the")
    print("balance through your own node. Consider shredding the CSV afterwards.")


if __name__ == "__main__":
    main()
