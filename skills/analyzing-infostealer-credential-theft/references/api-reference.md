# API Reference: Analyzing Infostealer Credential Theft

## Overview

`scripts/analyst.py` extracts strings from a sample and maps them to targeted artifacts (browser
credential stores, crypto wallets, application configs, credential APIs) and exfiltration channels
(Telegram, Discord webhooks, HTTP POST, FTP, SMTP). It reads bytes statically, defangs endpoints,
and executes nothing.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | regex, JSON, file IO |

## Core functions

### `profile(path)`
Returns targeted artifacts (grouped), exfiltration channels (defanged), and an infostealer
likelihood flag (≥2 target categories).

## Target categories

- **browser_credentials**: Chromium `Login Data`/`Cookies`/`Local State`, Firefox `key4.db`/`logins.json`.
- **crypto_wallets**: `wallet.dat`, Electrum/Exodus/MetaMask/Monero/Ledger.
- **applications**: FileZilla, OpenVPN, Telegram `tdata`, Discord, WinSCP, AnyDesk.
- **credential_api**: `CryptUnprotectData`, `CredEnumerate`, vault/LSA APIs.

## Usage

```bash
python scripts/analyst.py profile sample.bin
```

## Sources

- MITRE ATT&CK T1555.003 Credentials from Web Browsers — https://attack.mitre.org/techniques/T1555/003/
- MITRE ATT&CK T1539 Steal Web Session Cookie — https://attack.mitre.org/techniques/T1539/
- Browser/wallet artifact paths from public stealer family analyses
