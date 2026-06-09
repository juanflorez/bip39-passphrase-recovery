# bip39-passphrase-recovery

Recover a **forgotten BIP39 passphrase** (the optional "25th word" / "hidden
wallet" passphrase) when you still have your seed phrase and remember roughly
what the passphrase was — safely, on an air-gapped machine, without ever
typing your seed on anything connected to a network.

> **This recovers a forgotten _passphrase_, given a _known seed_.** It does
> **not** brute-force or "crack" an unknown seed phrase, and it cannot help
> if you've lost the seed itself. See [DISCLAIMER.md](DISCLAIMER.md).

## The problem

A BIP39 passphrase is mixed into your seed to derive a completely separate
wallet. Get one character wrong — a capital letter, a `!` instead of an `i`,
a trailing space — and you silently get a *different*, empty wallet. The
device gives no "wrong passphrase" error, because every passphrase is valid.

If you remember the *shape* of your passphrase (a word or two, your habits
with capitalisation or `l33t` substitutions) but not the exact string, the
number of plausible variants is too large to type one-by-one into a hardware
wallet. This project turns that fuzzy memory into a finite list and checks it
mechanically.

## How it works — and why it's safe

```
  ┌── on an AIR-GAPPED machine (seed never leaves it) ──┐   ┌── online ──┐
  │                                                     │   │            │
  gen_candidates.py  ──►  candidates.txt                │   │            │
                              │                          │   │            │
  derive_xpubs.py  ◄── your seed (typed here only)       │   │            │
        │                                                │   │            │
        └──►  xpubs.csv  ── watch-only, cannot spend ────┼──►│ scan_*.py  │
                                                         │   │     │      │
                                                         │   │   which    │
                                                         │   │ candidate  │
                                                         │   │ owns coins │
  └─────────────────────────────────────────────────────┘   └────────────┘
```

1. **Generate candidates** from the fragments you remember (`gen_candidates.py`).
2. **Derive watch-only xpubs** for every candidate on an offline machine
   (`derive_xpubs.py`). Your seed is typed *only here*, on a machine with no
   network. The only thing that crosses back is a CSV of **extended public
   keys** — they can reveal addresses but **cannot spend** anything.
3. **Scan** to see which candidate's xpub actually owns coins:
   - `scan_local.py` — against **your own Bitcoin Core node**. Private: it
     queries nothing off-host. **Strongly preferred.**
   - `scan_public.py` — against a public Blockbook explorer. Convenient but
     it **leaks your candidate xpubs (and thus your wallet) to a third party
     and your IP**. Use only if you accept that.
4. The scan reports a **candidate line number**, never the passphrase itself.
   You look the word up in your private `candidates.txt`, confirm it on your
   hardware wallet, and then **write it down somewhere durable**.

The seed is never stored, never sent, never put in a command-line argument
(so it can't land in shell history or `ps`). `derive_xpubs.py` is **Python
standard-library only** (no `pip`, no dependencies) specifically so it runs on
a clean live-USB OS with networking disabled, and it **refuses to run if it
detects an internet connection**. It validates your seed against the embedded
BIP39 wordlist and checksum before deriving, so a mistyped word aborts instead
of producing a wallet full of garbage.

## Requirements

- Python 3.8+ (standard library only — nothing to install for derive/generate).
- For the private scan: a **Bitcoin Core** node, fully synced. A *pruned* node
  is fine — `scantxoutset` works on the live UTXO set. The node only needs to
  be reachable by `bitcoin-cli` (pass `--cli` to customise the invocation).
- A live-USB OS (e.g. Ubuntu Desktop / Tails) for the air-gapped step.

## Quick start

```bash
# 1) candidate list — start NARROW, widen only if it misses.
#    (replace these example words with the fragments YOU remember)
python3 tools/gen_candidates.py summer dragon --case --plural --out candidates.txt

# 2) AIR-GAPPED: boot a live USB, disable networking, then:
python3 tools/derive_xpubs.py --selftest                      # must print ALL OK
python3 tools/derive_xpubs.py --candidates candidates.txt --out xpubs.csv --accounts 1
#   ^ prompts for your seed (hidden). Bring ONLY xpubs.csv back. Power off.

# 3) ONLINE: scan against your own node (private):
python3 tools/scan_local.py xpubs.csv --range 50
#   …or, accepting the privacy cost, against a public explorer:
python3 tools/scan_public.py xpubs.csv
```

### Sizing the search

Cost multiplies out as `candidates × purposes(≤4) × accounts × 2 chains ×
address-range`. Start with the plain words and `--accounts 1 --range 50`
(most wallets used account 0 and a handful of addresses); widen the mutation
flags, then `--accounts` / `--range`, only if nothing is found.
`gen_candidates.py` aborts past `--max` (default 500k) candidates so a careless
flag combination can't silently produce an un-scannable list.

## The tools

| Script | Runs on | Purpose |
|---|---|---|
| `gen_candidates.py` | anywhere | remembered fragments → `candidates.txt` |
| `derive_xpubs.py` | **air-gapped** | seed + candidates → watch-only `xpubs.csv` (stdlib only; self-tests against official BIP32/39/84/86 vectors; validates seed wordlist+checksum; refuses to run online) |
| `scan_local.py` | your node | `xpubs.csv` → which candidate owns UTXOs (private; one `scantxoutset` pass) |
| `scan_public.py` | online | same, via a public Blockbook explorer (**privacy-sacrificing**; skips taproot) |

Supports BIP44 (legacy `1…`), BIP49 (P2SH-segwit `3…`), BIP84
(native-segwit `bc1q…`) and BIP86 (taproot `bc1p…`) derivation paths.

## Verify before you trust it

This software touches the most sensitive thing you own. **Read the code** —
it's deliberately small and dependency-free. `derive_xpubs.py --selftest`
checks the crypto against the published BIP test vectors. You can cross-check
a derivation against an independent library (e.g. `bip-utils`) if you want a
second opinion before typing your seed.

## License

[MIT](LICENSE). Provided in good faith and **without any warranty**. Please
read [DISCLAIMER.md](DISCLAIMER.md) before use.
