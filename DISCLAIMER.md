# Disclaimer

**Read this in full before using this software.** By using it you accept the
terms below. This software is published in good faith to help people recover
access to wallets they own. It is not a product or a service, and no one
stands behind it commercially.

## No warranty

This software is provided **"AS IS", without warranty of any kind**, express
or implied, including but not limited to warranties of merchantability,
fitness for a particular purpose, and non-infringement, as stated in the
[MIT License](LICENSE). The authors and contributors make **no guarantee**
that it is correct, secure, complete, or fit for any purpose, and **no
guarantee that it will recover your passphrase or your funds**.

## No liability

To the maximum extent permitted by law, the authors and contributors are
**not liable for any loss or damage** of any kind arising from the use of, or
inability to use, this software — including but not limited to loss of
cryptocurrency or other funds, loss of access to wallets, data loss, hardware
or software malfunction, privacy loss, or any direct, indirect, incidental,
or consequential damages. **You use this software entirely at your own risk.**

## Not professional advice

Nothing here is financial, investment, legal, tax, or security advice. If the
funds at stake matter to you, consult a qualified professional and consider
independent, reputable recovery specialists.

## Use only on wallets you own

Use this software **only** to recover passphrases for wallets that **you own
and are lawfully authorised to access**. Using it — or any derivation,
scanning, or address-monitoring tool — against wallets, seeds, or keys that
are not yours may be **illegal** in your jurisdiction. You are solely
responsible for ensuring your use is lawful.

## Protect your seed — and watch for scams

- Your **seed phrase is the master key to your funds.** Anyone who learns it
  can steal everything. This software never asks you to send your seed
  anywhere, and you should be **deeply suspicious of anything that does.**
- Type your seed **only on an offline (air-gapped) machine** with networking
  disabled, ideally a live-USB session that is powered off afterward.
- **No legitimate tool, website, "wallet recovery service," support agent, or
  giveaway will ever ask for your seed phrase.** Every one that does is a
  scam. This is the single most common way people lose their coins.
- The watch-only `xpubs.csv` this tool produces cannot spend funds, but it
  **can reveal your wallet's addresses**. Treat it, and your `candidates.txt`,
  as private. The public-explorer scan (`scan_public.py`) discloses those
  xpubs to a third party by design — prefer your own node.

## Verify the code yourself

Because this software handles seed-adjacent material, **do not trust it
blindly.** Read the source — it is intentionally small and dependency-free.
Run `derive_xpubs.py --selftest` to check the cryptography against the
published BIP test vectors, and cross-check against an independent library if
you want further assurance before entering your seed.

## Backups

Cryptocurrency operations can be irreversible. **Back up your seed and any
existing wallet data before doing anything**, and never destroy your only
copy of a seed or passphrase based on the output of this or any tool.
