#!/usr/bin/env python3
"""Identify which candidate xpub owns coins, via a PUBLIC Blockbook explorer.

This is the privacy-sacrificing alternative to scan_local.py (which uses your
own node). It sends every candidate xpub to a third-party server (Trezor's
public Blockbook), which derives the addresses and reports balances. Use only
if you have ACCEPTED that the funded candidate — i.e. the wallet that holds
your coins — gets linked to your IP address by a third party. Prefer
scan_local.py against your own node whenever you can.

It NEVER prints the matching passphrase — only the candidate LINE NUMBER, which
you look up yourself in candidates.txt. (Printing the word would leak your
recovered passphrase into wherever this output lands.)

Note: Blockbook's xpub endpoint cannot take taproot (BIP86 / purpose 86)
xpubs — those rows are skipped here and must be scanned with scan_local.py.

Usage:
    python3 scan_public.py xpubs.csv
"""

import argparse
import csv
import json
import sys
import time
import urllib.request

# stored xpub (0488B21E) -> the version Blockbook needs to pick the script type
VER = {44: "0488B21E", 49: "049D7CB2", 84: "04B24746"}   # xpub / ypub / zpub
HOSTS = [f"btc{i}.trezor.io" for i in (1, 2, 3, 4, 5)]
UA = "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0"

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from derive_xpubs import _b58check_decode, _b58check_encode  # noqa: E402


def reversion(xpub, purpose):
    return _b58check_encode(bytes.fromhex(VER[purpose]) + _b58check_decode(xpub)[4:])


def query(xpub_conv, host):
    url = f"https://{host}/api/v2/xpub/{xpub_conv}?details=basic"
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=25) as r:
        return json.load(r)


def query_retry(xpub_conv, i):
    last = None
    for attempt in range(4):
        host = HOSTS[(i + attempt) % len(HOSTS)]
        try:
            return query(xpub_conv, host)
        except Exception as e:               # 403/429/timeout -> rotate + back off
            last = e
            time.sleep(0.5 * (attempt + 1))
    raise last


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("csv_file", help="xpubs CSV from derive_candidate_xpubs.py")
    ap.add_argument("--delay", type=float, default=0.2, help="seconds between requests")
    args = ap.parse_args()

    rows = list(csv.DictReader(open(args.csv_file)))
    skipped = sum(1 for r in rows if int(r["purpose"]) not in VER)
    if skipped:
        print(f"NOTE: skipping {skipped} taproot (purpose 86) rows — Blockbook's "
              f"xpub endpoint can't take them; scan those on the own node instead.",
              file=sys.stderr)
        rows = [r for r in rows if int(r["purpose"]) in VER]
    hits, errors = [], 0
    for i, r in enumerate(rows):
        cand, purpose, acct = int(r["candidate"]), int(r["purpose"]), int(r["account"])
        try:
            d = query_retry(reversion(r["xpub"], purpose), i)
            bal = int(d.get("balance", "0"))
            recv = int(d.get("totalReceived", "0"))
            txs = int(d.get("txs", 0))
            if bal > 0 or recv > 0 or txs > 0:
                hits.append((cand, purpose, acct, bal, recv, txs))
                print(f"  >>> HIT  candidate #{cand}  m/{purpose}'/0'/{acct}'  "
                      f"balance={bal/1e8:.8f} received={recv/1e8:.8f} txs={txs}")
        except Exception as e:
            errors += 1
            print(f"  !! error candidate #{cand} purpose {purpose} acct {acct}: {e}",
                  file=sys.stderr)
        if (i + 1) % 50 == 0:
            print(f"  ...{i + 1}/{len(rows)} queried", file=sys.stderr)
        time.sleep(args.delay)

    print(f"\nDone. {len(rows)} xpubs queried, {errors} errors, {len(hits)} hit(s).")
    if not hits:
        print("No candidate shows any on-chain activity. Either the passphrase isn't")
        print("in the list, or the wallet used a deeper account/address range than")
        print("derived. Widen with derive --accounts N and re-run.")
        return
    print("\nFUNDED / ACTIVE candidate line number(s) — look the word up yourself in")
    print("candidates.txt (NOT printed here on purpose):")
    for cand, purpose, acct, bal, recv, txs in sorted(set(hits)):
        kind = {44: "legacy", 49: "p2sh-segwit", 84: "native-segwit"}[purpose]
        print(f"  candidates.txt line #{cand}  ({kind}, account {acct})  "
              f"balance {bal/1e8:.8f} BTC, {txs} tx(s)")


if __name__ == "__main__":
    main()
