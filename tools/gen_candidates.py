#!/usr/bin/env python3
"""Generate a candidate passphrase list from the fragments you remember.

You forgot your BIP39 passphrase but you remember *roughly* what it was — a
word or two, maybe how you tend to capitalise or substitute characters. This
expands those root words into the combinations worth trying, so the derive +
scan steps can check them all mechanically instead of you guessing by hand.

Give it one or more ROOT WORDS and switch on the mutation families that match
how you think you wrote the passphrase. Every family is OFF by default — start
narrow (the plain words) and widen only as needed, because the candidate count
multiplies fast and every candidate becomes (purposes × accounts × 2 chains ×
address-range) descriptors to scan later.

    # just the words, plus their plural and three casings:
    python3 gen_candidates.py summer dragon --case --plural --out candidates.txt

    # add digit leet (a->4 e->3 i->1 l->1 o->0 s->5 t->7) and symbol leet
    # (a->@ i->! l->! s->$), applied independently per position:
    python3 gen_candidates.py summer --case --leet --symbols --out candidates.txt

    # add on-device typing slips (alphabet-neighbour, dropped, doubled char)
    # and common trailing strings:
    python3 gen_candidates.py hunter2 --typos --suffix '!' '$' '1' --out c.txt

Output: one candidate per line, deduplicated, sorted. A blank first line is
added if --include-empty is set (tests the "no passphrase" / base account).

NOTHING here is secret on its own — a candidate list is useless without your
seed — but it still describes your guessing space, so treat it as private.
"""

import argparse
import itertools
import string
import sys

# Per-position character substitutions. Keys are lowercase; matching is
# case-insensitive so ALLCAPS forms get the same treatment. The original
# character is always kept as an option too.
DIGIT_LEET = {"a": ["4"], "b": ["8"], "e": ["3"], "g": ["9"], "i": ["1"],
              "l": ["1"], "o": ["0"], "s": ["5"], "t": ["7"], "z": ["2"]}
SYMBOL_LEET = {"a": ["@"], "i": ["!"], "l": ["!"], "s": ["$"]}


def merge_subs(*maps):
    out = {}
    for m in maps:
        for k, v in m.items():
            out.setdefault(k, [])
            out[k] += [c for c in v if c not in out[k]]
    return out


def case_forms(word):
    """lowercase, Capitalized, ALLCAPS — deduplicated."""
    return dict.fromkeys((word.lower(), word[:1].upper() + word[1:].lower(),
                          word.upper())).keys()


def substitute(word, sub_map):
    """Cartesian product of every per-position substitution choice."""
    options = []
    for ch in word:
        alts = [ch] + sub_map.get(ch.lower(), [])
        options.append(list(dict.fromkeys(alts)))
    return {"".join(combo) for combo in itertools.product(*options)}


def neighbours(ch):
    for alpha in (string.ascii_lowercase, string.ascii_uppercase):
        if ch in alpha:
            i = alpha.index(ch)
            return {alpha[(i - 1) % 26], alpha[(i + 1) % 26]}
    return set()


def typo_edits(word):
    """Single-character slips: alphabet-neighbour, dropped, doubled."""
    out = set()
    for i, ch in enumerate(word):
        for n in neighbours(ch):
            out.add(word[:i] + n + word[i + 1:])     # neighbour
        out.add(word[:i] + word[i + 1:])             # dropped
        out.add(word[:i + 1] + word[i:])             # doubled
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("words", nargs="+", help="root word(s) you remember")
    ap.add_argument("--out", help="output file (default: stdout)")
    ap.add_argument("--case", action="store_true",
                    help="also try lowercase / Capitalized / ALLCAPS")
    ap.add_argument("--plural", action="store_true",
                    help="also try each word with a trailing 's'")
    ap.add_argument("--leet", action="store_true",
                    help="per-position digit substitutions (a->4 e->3 i->1 ...)")
    ap.add_argument("--symbols", action="store_true",
                    help="per-position symbol substitutions (a->@ i->! l->! s->$)")
    ap.add_argument("--typos", action="store_true",
                    help="single-char slips: neighbour key, dropped, doubled")
    ap.add_argument("--suffix", nargs="+", default=[], metavar="STR",
                    help="also append each of these strings (e.g. '!' '$' '1')")
    ap.add_argument("--spaces", action="store_true",
                    help="also try a leading and a trailing space")
    ap.add_argument("--include-empty", action="store_true",
                    help="add a blank line (the empty / no-passphrase case)")
    ap.add_argument("--max", type=int, default=500_000,
                    help="abort if the list would exceed this many candidates "
                         "(default 500000; raise deliberately)")
    args = ap.parse_args()

    # 1. base words (+ optional plural)
    bases = set(args.words)
    if args.plural:
        bases |= {w + "s" for w in args.words}

    # 2. casing
    cased = set()
    for w in bases:
        cased |= set(case_forms(w)) if args.case else {w}

    # 3. per-position substitutions (leet / symbol), independently combinable
    sub_map = merge_subs(*([DIGIT_LEET] if args.leet else []),
                         *([SYMBOL_LEET] if args.symbols else []))
    subbed = set()
    for w in cased:
        subbed |= substitute(w, sub_map) if sub_map else {w}

    # 4. typo edits, taken on the cased words (not the substituted ones, to
    #    bound the size — a typo AND a leet sub in the same word is unlikely)
    if args.typos:
        for w in cased:
            subbed |= typo_edits(w)

    # 5. suffixes (each candidate, with and without)
    if args.suffix:
        subbed |= {w + s for w in set(subbed) for s in args.suffix}

    # 6. edge spaces
    if args.spaces:
        subbed |= {" " + w for w in set(subbed)} | {w + " " for w in set(subbed)}

    candidates = sorted(subbed)
    if len(candidates) > args.max:
        sys.exit(f"ABORT: {len(candidates)} candidates exceeds --max {args.max}. "
                 "Narrow the mutation flags, or raise --max if you really mean it.")
    if args.include_empty:
        candidates = [""] + candidates

    out = open(args.out, "w", encoding="utf-8") if args.out else sys.stdout
    try:
        out.write("\n".join(candidates) + "\n")
    finally:
        if args.out:
            out.close()
    where = args.out if args.out else "stdout"
    sys.stderr.write(f"wrote {len(candidates)} candidates to {where}\n")


if __name__ == "__main__":
    main()
