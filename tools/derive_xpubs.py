#!/usr/bin/env python3
"""Derive BIP44/49/84/86 account xpubs for each candidate BIP39 passphrase.

AIR-GAPPED USE ONLY. This script is for recovering a forgotten BIP39
passphrase when you know the mnemonic and have a shortlist of candidates.
It never writes the mnemonic or the passphrases anywhere: the output CSV
contains only candidate line-numbers and watch-only xpubs.

Design constraints:
  - Python 3.8+ standard library ONLY (no pip) so it runs on any live-USB
    OS without network access. All crypto (secp256k1, RIPEMD-160, base58)
    is implemented inline and verified by --selftest against the official
    BIP32 / BIP39 / BIP84 / BIP86 test vectors.
  - The mnemonic is validated against the embedded BIP39 English wordlist
    AND its checksum before anything is derived — a mistyped word aborts
    instead of silently deriving garbage xpubs.
  - The mnemonic is prompted interactively with HIDDEN input by default and
    is never taken as a command-line argument (keeps it out of shell history
    and `ps`). Pass --show-mnemonic to echo it visibly — only sensible when
    you are alone on an air-gapped machine that is powered off afterwards.

Usage (on the OFFLINE machine):
    python3 derive_xpubs.py --selftest                    # ALWAYS run first
    python3 derive_xpubs.py --candidates candidates.txt --out xpubs.csv

candidates.txt: one passphrase per line, order preserved. Lines are used
VERBATIM (only the trailing newline is stripped) — leading/trailing spaces
are significant in BIP39 passphrases, so keep deliberate variants as
separate lines. Blank lines are kept too (a blank line = "no passphrase").

Output CSV columns: candidate (1-based line number), purpose (44/49/84/86),
account, xpub. Carry ONLY this file back to the online machine.
"""

import argparse
import csv
import hashlib
import hmac
import struct
import sys
import unicodedata

HARDENED = 0x80000000

# ── BIP39 English wordlist (2048 words; integrity checked in selftest against
#    the official file's sha256) ──────────────────────────────────────────────
_BIP39_WORDLIST = """
abandon ability able about above absent absorb abstract absurd abuse access
accident account accuse achieve acid acoustic acquire across act action actor
actress actual adapt add addict address adjust admit adult advance advice
aerobic affair afford afraid again age agent agree ahead aim air airport aisle
alarm album alcohol alert alien all alley allow almost alone alpha already
also alter always amateur amazing among amount amused analyst anchor ancient
anger angle angry animal ankle announce annual another answer antenna antique
anxiety any apart apology appear apple approve april arch arctic area arena
argue arm armed armor army around arrange arrest arrive arrow art artefact
artist artwork ask aspect assault asset assist assume asthma athlete atom
attack attend attitude attract auction audit august aunt author auto autumn
average avocado avoid awake aware away awesome awful awkward axis baby
bachelor bacon badge bag balance balcony ball bamboo banana banner bar barely
bargain barrel base basic basket battle beach bean beauty because become beef
before begin behave behind believe below belt bench benefit best betray better
between beyond bicycle bid bike bind biology bird birth bitter black blade
blame blanket blast bleak bless blind blood blossom blouse blue blur blush
board boat body boil bomb bone bonus book boost border boring borrow boss
bottom bounce box boy bracket brain brand brass brave bread breeze brick
bridge brief bright bring brisk broccoli broken bronze broom brother brown
brush bubble buddy budget buffalo build bulb bulk bullet bundle bunker burden
burger burst bus business busy butter buyer buzz cabbage cabin cable cactus
cage cake call calm camera camp can canal cancel candy cannon canoe canvas
canyon capable capital captain car carbon card cargo carpet carry cart case
cash casino castle casual cat catalog catch category cattle caught cause
caution cave ceiling celery cement census century cereal certain chair chalk
champion change chaos chapter charge chase chat cheap check cheese chef cherry
chest chicken chief child chimney choice choose chronic chuckle chunk churn
cigar cinnamon circle citizen city civil claim clap clarify claw clay clean
clerk clever click client cliff climb clinic clip clock clog close cloth cloud
clown club clump cluster clutch coach coast coconut code coffee coil coin
collect color column combine come comfort comic common company concert conduct
confirm congress connect consider control convince cook cool copper copy coral
core corn correct cost cotton couch country couple course cousin cover coyote
crack cradle craft cram crane crash crater crawl crazy cream credit creek crew
cricket crime crisp critic crop cross crouch crowd crucial cruel cruise
crumble crunch crush cry crystal cube culture cup cupboard curious current
curtain curve cushion custom cute cycle dad damage damp dance danger daring
dash daughter dawn day deal debate debris decade december decide decline
decorate decrease deer defense define defy degree delay deliver demand demise
denial dentist deny depart depend deposit depth deputy derive describe desert
design desk despair destroy detail detect develop device devote diagram dial
diamond diary dice diesel diet differ digital dignity dilemma dinner dinosaur
direct dirt disagree discover disease dish dismiss disorder display distance
divert divide divorce dizzy doctor document dog doll dolphin domain donate
donkey donor door dose double dove draft dragon drama drastic draw dream dress
drift drill drink drip drive drop drum dry duck dumb dune during dust dutch
duty dwarf dynamic eager eagle early earn earth easily east easy echo ecology
economy edge edit educate effort egg eight either elbow elder electric elegant
element elephant elevator elite else embark embody embrace emerge emotion
employ empower empty enable enact end endless endorse enemy energy enforce
engage engine enhance enjoy enlist enough enrich enroll ensure enter entire
entry envelope episode equal equip era erase erode erosion error erupt escape
essay essence estate eternal ethics evidence evil evoke evolve exact example
excess exchange excite exclude excuse execute exercise exhaust exhibit exile
exist exit exotic expand expect expire explain expose express extend extra eye
eyebrow fabric face faculty fade faint faith fall false fame family famous fan
fancy fantasy farm fashion fat fatal father fatigue fault favorite feature
february federal fee feed feel female fence festival fetch fever few fiber
fiction field figure file film filter final find fine finger finish fire firm
first fiscal fish fit fitness fix flag flame flash flat flavor flee flight
flip float flock floor flower fluid flush fly foam focus fog foil fold follow
food foot force forest forget fork fortune forum forward fossil foster found
fox fragile frame frequent fresh friend fringe frog front frost frown frozen
fruit fuel fun funny furnace fury future gadget gain galaxy gallery game gap
garage garbage garden garlic garment gas gasp gate gather gauge gaze general
genius genre gentle genuine gesture ghost giant gift giggle ginger giraffe
girl give glad glance glare glass glide glimpse globe gloom glory glove glow
glue goat goddess gold good goose gorilla gospel gossip govern gown grab grace
grain grant grape grass gravity great green grid grief grit grocery group grow
grunt guard guess guide guilt guitar gun gym habit hair half hammer hamster
hand happy harbor hard harsh harvest hat have hawk hazard head health heart
heavy hedgehog height hello helmet help hen hero hidden high hill hint hip
hire history hobby hockey hold hole holiday hollow home honey hood hope horn
horror horse hospital host hotel hour hover hub huge human humble humor
hundred hungry hunt hurdle hurry hurt husband hybrid ice icon idea identify
idle ignore ill illegal illness image imitate immense immune impact impose
improve impulse inch include income increase index indicate indoor industry
infant inflict inform inhale inherit initial inject injury inmate inner
innocent input inquiry insane insect inside inspire install intact interest
into invest invite involve iron island isolate issue item ivory jacket jaguar
jar jazz jealous jeans jelly jewel job join joke journey joy judge juice jump
jungle junior junk just kangaroo keen keep ketchup key kick kid kidney kind
kingdom kiss kit kitchen kite kitten kiwi knee knife knock know lab label
labor ladder lady lake lamp language laptop large later latin laugh laundry
lava law lawn lawsuit layer lazy leader leaf learn leave lecture left leg
legal legend leisure lemon lend length lens leopard lesson letter level liar
liberty library license life lift light like limb limit link lion liquid list
little live lizard load loan lobster local lock logic lonely long loop lottery
loud lounge love loyal lucky luggage lumber lunar lunch luxury lyrics machine
mad magic magnet maid mail main major make mammal man manage mandate mango
mansion manual maple marble march margin marine market marriage mask mass
master match material math matrix matter maximum maze meadow mean measure meat
mechanic medal media melody melt member memory mention menu mercy merge merit
merry mesh message metal method middle midnight milk million mimic mind
minimum minor minute miracle mirror misery miss mistake mix mixed mixture
mobile model modify mom moment monitor monkey monster month moon moral more
morning mosquito mother motion motor mountain mouse move movie much muffin
mule multiply muscle museum mushroom music must mutual myself mystery myth
naive name napkin narrow nasty nation nature near neck need negative neglect
neither nephew nerve nest net network neutral never news next nice night noble
noise nominee noodle normal north nose notable note nothing notice novel now
nuclear number nurse nut oak obey object oblige obscure observe obtain obvious
occur ocean october odor off offer office often oil okay old olive olympic
omit once one onion online only open opera opinion oppose option orange orbit
orchard order ordinary organ orient original orphan ostrich other outdoor
outer output outside oval oven over own owner oxygen oyster ozone pact paddle
page pair palace palm panda panel panic panther paper parade parent park
parrot party pass patch path patient patrol pattern pause pave payment peace
peanut pear peasant pelican pen penalty pencil people pepper perfect permit
person pet phone photo phrase physical piano picnic picture piece pig pigeon
pill pilot pink pioneer pipe pistol pitch pizza place planet plastic plate
play please pledge pluck plug plunge poem poet point polar pole police pond
pony pool popular portion position possible post potato pottery poverty powder
power practice praise predict prefer prepare present pretty prevent price
pride primary print priority prison private prize problem process produce
profit program project promote proof property prosper protect proud provide
public pudding pull pulp pulse pumpkin punch pupil puppy purchase purity
purpose purse push put puzzle pyramid quality quantum quarter question quick
quit quiz quote rabbit raccoon race rack radar radio rail rain raise rally
ramp ranch random range rapid rare rate rather raven raw razor ready real
reason rebel rebuild recall receive recipe record recycle reduce reflect
reform refuse region regret regular reject relax release relief rely remain
remember remind remove render renew rent reopen repair repeat replace report
require rescue resemble resist resource response result retire retreat return
reunion reveal review reward rhythm rib ribbon rice rich ride ridge rifle
right rigid ring riot ripple risk ritual rival river road roast robot robust
rocket romance roof rookie room rose rotate rough round route royal rubber
rude rug rule run runway rural sad saddle sadness safe sail salad salmon salon
salt salute same sample sand satisfy satoshi sauce sausage save say scale scan
scare scatter scene scheme school science scissors scorpion scout scrap screen
script scrub sea search season seat second secret section security seed seek
segment select sell seminar senior sense sentence series service session
settle setup seven shadow shaft shallow share shed shell sheriff shield shift
shine ship shiver shock shoe shoot shop short shoulder shove shrimp shrug
shuffle shy sibling sick side siege sight sign silent silk silly silver
similar simple since sing siren sister situate six size skate sketch ski skill
skin skirt skull slab slam sleep slender slice slide slight slim slogan slot
slow slush small smart smile smoke smooth snack snake snap sniff snow soap
soccer social sock soda soft solar soldier solid solution solve someone song
soon sorry sort soul sound soup source south space spare spatial spawn speak
special speed spell spend sphere spice spider spike spin spirit split spoil
sponsor spoon sport spot spray spread spring spy square squeeze squirrel
stable stadium staff stage stairs stamp stand start state stay steak steel
stem step stereo stick still sting stock stomach stone stool story stove
strategy street strike strong struggle student stuff stumble style subject
submit subway success such sudden suffer sugar suggest suit summer sun sunny
sunset super supply supreme sure surface surge surprise surround survey
suspect sustain swallow swamp swap swarm swear sweet swift swim swing switch
sword symbol symptom syrup system table tackle tag tail talent talk tank tape
target task taste tattoo taxi teach team tell ten tenant tennis tent term test
text thank that theme then theory there they thing this thought three thrive
throw thumb thunder ticket tide tiger tilt timber time tiny tip tired tissue
title toast tobacco today toddler toe together toilet token tomato tomorrow
tone tongue tonight tool tooth top topic topple torch tornado tortoise toss
total tourist toward tower town toy track trade traffic tragic train transfer
trap trash travel tray treat tree trend trial tribe trick trigger trim trip
trophy trouble truck true truly trumpet trust truth try tube tuition tumble
tuna tunnel turkey turn turtle twelve twenty twice twin twist two type typical
ugly umbrella unable unaware uncle uncover under undo unfair unfold unhappy
uniform unique unit universe unknown unlock until unusual unveil update
upgrade uphold upon upper upset urban urge usage use used useful useless usual
utility vacant vacuum vague valid valley valve van vanish vapor various vast
vault vehicle velvet vendor venture venue verb verify version very vessel
veteran viable vibrant vicious victory video view village vintage violin
virtual virus visa visit visual vital vivid vocal voice void volcano volume
vote voyage wage wagon wait walk wall walnut want warfare warm warrior wash
wasp waste water wave way wealth weapon wear weasel weather web wedding
weekend weird welcome west wet whale what wheat wheel when where whip whisper
wide width wife wild will win window wine wing wink winner winter wire wisdom
wise wish witness wolf woman wonder wood wool word work world worry worth wrap
wreck wrestle wrist write wrong yard year yellow you young youth zebra zero
zone zoo
""".split()
_BIP39_INDEX = {w: i for i, w in enumerate(_BIP39_WORDLIST)}


# ── secp256k1 (affine, double-and-add; fine for ~thousands of mults) ──────
_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)


def _point_add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    (x1, y1), (x2, y2) = a, b
    if x1 == x2 and (y1 + y2) % _P == 0:
        return None  # point at infinity
    if a == b:
        lam = (3 * x1 * x1) * pow(2 * y1, -1, _P) % _P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, _P) % _P
    x3 = (lam * lam - x1 - x2) % _P
    y3 = (lam * (x1 - x3) - y1) % _P
    return (x3, y3)


def _scalar_mult(k, point=_G):
    result, addend = None, point
    while k:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        k >>= 1
    return result


def _ser_pubkey(point):
    x, y = point
    return bytes([2 + (y & 1)]) + x.to_bytes(32, "big")


# ── RIPEMD-160 (pure python; OpenSSL 3 often ships without it) ────────────
def _ripemd160(data):
    try:
        return hashlib.new("ripemd160", data).digest()
    except ValueError:
        return _ripemd160_pure(data)


_RL = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
]
_RR = [
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
]
_SL = [
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
]
_SR = [
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
]
_KL = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]
_KR = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000]


def _rol(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _rmd_f(j, x, y, z):
    if j < 16:
        return x ^ y ^ z
    if j < 32:
        return (x & y) | (~x & z)
    if j < 48:
        return (x | ~y) ^ z
    if j < 64:
        return (x & z) | (y & ~z)
    return x ^ (y | ~z)


def _ripemd160_pure(data):
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    msg = data + b"\x80"
    msg += b"\x00" * ((56 - len(msg) % 64) % 64)
    msg += struct.pack("<Q", len(data) * 8)
    for off in range(0, len(msg), 64):
        x = struct.unpack("<16I", msg[off:off + 64])
        al, bl, cl, dl, el = h
        ar, br, cr, dr, er = h
        for j in range(80):
            t = (_rol((al + _rmd_f(j, bl, cl, dl) + x[_RL[j]] + _KL[j // 16])
                      & 0xFFFFFFFF, _SL[j]) + el) & 0xFFFFFFFF
            al, el, dl, cl, bl = el, dl, _rol(cl, 10), bl, t
            t = (_rol((ar + _rmd_f(79 - j, br, cr, dr) + x[_RR[j]] + _KR[j // 16])
                      & 0xFFFFFFFF, _SR[j]) + er) & 0xFFFFFFFF
            ar, er, dr, cr, br = er, dr, _rol(cr, 10), br, t
        h = [
            (h[1] + cl + dr) & 0xFFFFFFFF,
            (h[2] + dl + er) & 0xFFFFFFFF,
            (h[3] + el + ar) & 0xFFFFFFFF,
            (h[4] + al + br) & 0xFFFFFFFF,
            (h[0] + bl + cr) & 0xFFFFFFFF,
        ]
    return struct.pack("<5I", *h)


def _hash160(b):
    return _ripemd160(hashlib.sha256(b).digest())


# ── base58check ───────────────────────────────────────────────────────────
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58check_encode(payload):
    data = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    pad = len(data) - len(data.lstrip(b"\x00"))
    return "1" * pad + out


def _b58check_decode(s):
    n = 0
    for ch in s:
        n = n * 58 + _B58.index(ch)
    data = n.to_bytes((n.bit_length() + 7) // 8, "big")
    data = b"\x00" * (len(s) - len(s.lstrip("1"))) + data
    payload, chk = data[:-4], data[-4:]
    if hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] != chk:
        raise ValueError("bad base58 checksum")
    return payload


# ── BIP39 / BIP32 ─────────────────────────────────────────────────────────
def bip39_checksum_ok(words):
    """True iff the mnemonic's embedded checksum is valid (BIP39 §Generating)."""
    n = 0
    for w in words:
        n = n << 11 | _BIP39_INDEX[w]
    cs_bits = len(words) * 11 // 33
    entropy = (n >> cs_bits).to_bytes(cs_bits * 4, "big")
    return n & ((1 << cs_bits) - 1) == hashlib.sha256(entropy).digest()[0] >> (8 - cs_bits)


def bip39_seed(mnemonic, passphrase):
    m = unicodedata.normalize("NFKD", " ".join(mnemonic.split()))
    salt = unicodedata.normalize("NFKD", "mnemonic" + passphrase)
    return hashlib.pbkdf2_hmac("sha512", m.encode(), salt.encode(), 2048, 64)


def _master_key(seed):
    i = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    return int.from_bytes(i[:32], "big"), i[32:]


def _ckd_priv(k, c, index):
    if index >= HARDENED:
        data = b"\x00" + k.to_bytes(32, "big") + index.to_bytes(4, "big")
    else:
        data = _ser_pubkey(_scalar_mult(k)) + index.to_bytes(4, "big")
    i = hmac.new(c, data, hashlib.sha512).digest()
    child = (int.from_bytes(i[:32], "big") + k) % _N
    if child == 0 or int.from_bytes(i[:32], "big") >= _N:
        raise ValueError("invalid child key (astronomically unlikely)")
    return child, i[32:]


def _ser_xpub(depth, parent_fp, child_num, chaincode, pubkey):
    payload = (bytes.fromhex("0488B21E") + bytes([depth]) + parent_fp
               + child_num.to_bytes(4, "big") + chaincode + pubkey)
    return _b58check_encode(payload)


def account_xpub(seed, purpose, account):
    """xpub at m/purpose'/0'/account' (coin type 0 = Bitcoin mainnet)."""
    k, c = _master_key(seed)
    for idx in (HARDENED + purpose, HARDENED + 0):
        k, c = _ckd_priv(k, c, idx)
    parent_fp = _hash160(_ser_pubkey(_scalar_mult(k)))[:4]
    ka, ca = _ckd_priv(k, c, HARDENED + account)
    return _ser_xpub(3, parent_fp, HARDENED + account, ca, _ser_pubkey(_scalar_mult(ka)))


# ── selftest against official test vectors ────────────────────────────────
def selftest():
    # RIPEMD-160 (force the pure implementation; also exercise the wrapper)
    assert _ripemd160_pure(b"abc").hex() == "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"
    assert _ripemd160_pure(b"").hex() == "9c1185a5c5e9fc54612808977ee8f548b2258d31"
    assert _ripemd160(b"abc").hex() == "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"

    # BIP39 test vector (Trezor reference), passphrase "TREZOR"
    seed = bip39_seed(
        "abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon about", "TREZOR")
    assert seed.hex() == (
        "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f"
        "09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04")

    # BIP32 test vector 1: chain m and m/0'
    seed32 = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    k, c = _master_key(seed32)
    assert _ser_xpub(0, b"\x00" * 4, 0, c, _ser_pubkey(_scalar_mult(k))) == (
        "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ES"
        "FjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8")
    fp = _hash160(_ser_pubkey(_scalar_mult(k)))[:4]
    k0, c0 = _ckd_priv(k, c, HARDENED + 0)
    assert _ser_xpub(1, fp, HARDENED + 0, c0, _ser_pubkey(_scalar_mult(k0))) == (
        "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwB"
        "ZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw")

    # BIP84 test vector: full pipeline mnemonic -> m/84'/0'/0' xpub.
    # The spec publishes a zpub; same key material, different version
    # bytes — convert and compare.
    zpub = ("zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r"
            "1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs")
    expected = _b58check_encode(bytes.fromhex("0488B21E") + _b58check_decode(zpub)[4:])
    got = account_xpub(bip39_seed(
        "abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon about", ""), 84, 0)
    assert got == expected

    # BIP39 wordlist integrity (sha256 of the official english.txt) + checksum
    # validation against the all-zero-entropy 12- and 24-word vectors.
    assert len(_BIP39_WORDLIST) == 2048
    assert hashlib.sha256(("\n".join(_BIP39_WORDLIST) + "\n").encode()).hexdigest() == (
        "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda")
    assert bip39_checksum_ok(("abandon " * 11 + "about").split())
    assert bip39_checksum_ok(("abandon " * 23 + "art").split())
    assert not bip39_checksum_ok(["abandon"] * 12)          # bad checksum
    assert not bip39_checksum_ok(("abandon " * 11 + "art").split())  # wrong last word

    # BIP86 test vector (taproot): the spec publishes the m/86'/0'/0' account
    # xpub for the same mnemonic directly — full-pipeline check like BIP84.
    got = account_xpub(bip39_seed(
        "abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon about", ""), 86, 0)
    assert got == (
        "xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVk"
        "y7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ")

    print("selftest: ALL OK (RIPEMD-160, base58check, BIP39+wordlist+checksum, "
          "BIP32, BIP84, BIP86)")


# ── main ──────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--selftest", action="store_true",
                    help="verify against official test vectors and exit")
    ap.add_argument("--candidates", help="file with one candidate passphrase per line")
    ap.add_argument("--out", help="output CSV (candidate,purpose,account,xpub)")
    ap.add_argument("--accounts", type=int, default=3,
                    help="derive accounts 0..N-1 per purpose (default 3)")
    ap.add_argument("--show-mnemonic", action="store_true",
                    help="echo the mnemonic as you type it (default: hidden). "
                         "Only use this alone on an air-gapped machine.")
    args = ap.parse_args()

    if args.selftest:
        selftest()
        return
    if not (args.candidates and args.out):
        ap.error("--candidates and --out are required (or use --selftest)")

    # Refuse to run if the machine looks online — belt and braces.
    try:
        import socket
        s = socket.create_connection(("1.1.1.1", 53), timeout=2)
        s.close()
        sys.exit("ABORT: this machine has internet access. Run air-gapped only.")
    except OSError:
        pass  # good: no network

    selftest()  # never produce output from an unverified build

    with open(args.candidates, encoding="utf-8") as f:
        candidates = [line.rstrip("\n") for line in f]
    if not candidates:
        sys.exit("candidates file is empty")

    if args.show_mnemonic:
        mnemonic = input("Mnemonic (words separated by spaces — input is VISIBLE): ")
    else:
        import getpass
        mnemonic = getpass.getpass("Mnemonic (words separated by spaces — input hidden): ")
    words = mnemonic.split()
    if len(words) not in (12, 18, 24):
        sys.exit(f"expected 12/18/24 words, got {len(words)} — aborting")
    bad = [f"word #{i}: {w!r}" for i, w in enumerate(words, 1) if w not in _BIP39_INDEX]
    if bad:
        sys.exit("not in the BIP39 English wordlist (words are all-lowercase):\n  "
                 + "\n  ".join(bad) + "\naborting")
    if not bip39_checksum_ok(words):
        sys.exit("BIP39 checksum FAILED — a word is mistyped, swapped with a "
                 "near-miss (e.g. acid/arid), or out of order. Aborting.")

    rows = []
    for i, pw in enumerate(candidates, start=1):
        seed = bip39_seed(mnemonic, pw)
        for purpose in (44, 49, 84, 86):
            for account in range(args.accounts):
                rows.append((i, purpose, account, account_xpub(seed, purpose, account)))
        print(f"\rcandidate {i}/{len(candidates)}", end="", flush=True)
    print()

    with open(args.out, "w", newline="") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(["candidate", "purpose", "account", "xpub"])
        w.writerows(rows)
    print(f"wrote {len(rows)} xpubs to {args.out}")
    print("Carry ONLY this CSV to the online machine. The candidate column is the")
    print("1-based line number in your candidates file — keep that file private.")


if __name__ == "__main__":
    main()
