#!/usr/bin/env python3
"""Regression test for issue #1: scan_local must attribute found UTXOs to a
candidate via the resolved descriptor's key-origin fingerprint, not by
substring-matching the input xpub.

Run: python3 tests/test_scan_mapping.py   (stdlib only, no pytest needed)
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "tools"))

from derive_xpubs import account_xpub, bip39_seed                      # noqa: E402
from scan_local import attribute_unspents, xpub_fingerprint            # noqa: E402

# Two candidate xpubs from the standard BIP test mnemonic (public test vector
# data — no real wallet involved). Candidate #7 is the "funded" one.
MNEMONIC = ("abandon abandon abandon abandon abandon abandon abandon abandon "
            "abandon abandon abandon about")
XPUB_FUNDED = account_xpub(bip39_seed(MNEMONIC, "alpha"), 84, 0)   # candidate 7
XPUB_OTHER = account_xpub(bip39_seed(MNEMONIC, "beta"), 84, 0)     # candidate 3

rows = [(3, 84, 0, XPUB_OTHER), (7, 84, 0, XPUB_FUNDED)]


def resolved_desc(xpub, chain, index):
    """How bitcoind's scantxoutset reports a hit: resolved derived key with a
    [fingerprint/chain/index] origin tag — the input xpub does NOT appear."""
    fp = xpub_fingerprint(xpub)
    return f"wpkh([{fp}/{chain}/{index}]02deadbeef{index:056d})#chksum00"


def test_fix_attributes_hit_to_correct_candidate():
    unspents = [
        {"desc": resolved_desc(XPUB_FUNDED, 0, 0), "amount": 0.03},
        {"desc": resolved_desc(XPUB_FUNDED, 0, 1), "amount": 0.02149922},
    ]
    totals, unmapped = attribute_unspents(rows, unspents)
    assert not unmapped, f"nothing should be unmapped, got {unmapped}"
    assert (7, 84, 0) in totals, f"candidate 7 should be credited, got {totals}"
    amount, count = totals[(7, 84, 0)]
    assert count == 2, count
    assert abs(amount - 0.05149922) < 1e-12, amount
    assert (3, 84, 0) not in totals, "the unfunded candidate must not appear"
    print("  ok: funded UTXOs correctly attributed to candidate #7 "
          f"({amount:.8f} BTC, {count} UTXOs)")


def test_reproduces_old_bug_premise():
    # The pre-fix code did `xpub in desc`; prove the xpub is NOT a substring of
    # the resolved descriptor (which is exactly why the old code reported a miss).
    desc = resolved_desc(XPUB_FUNDED, 0, 0)
    assert XPUB_FUNDED not in desc, "xpub must not appear in resolved desc"
    print("  ok: input xpub is absent from the resolved descriptor "
          "(the old substring match could never have worked)")


def test_unknown_fingerprint_is_unmapped_not_crash():
    unspents = [{"desc": "wpkh([deadbeef/0/0]02aa...)#x", "amount": 1.0}]
    totals, unmapped = attribute_unspents(rows, unspents)
    assert not totals and len(unmapped) == 1
    print("  ok: an unrelated fingerprint is reported as unmapped, not crediting anyone")


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            print(f"- {name}")
            fn()
    print("\nALL TESTS PASSED")
