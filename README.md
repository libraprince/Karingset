# Karingset

Karing / sing-box Rule Set generator based on Johnshall Shadowrocket `lazy.conf`.

## What it does

- Pulls the current Johnshall `lazy.conf` every day.
- Downloads the referenced RULE-SET lists from their upstream sources.
- Converts domain / IP rules into sing-box source JSON.
- Compiles the JSON into `.srs` with sing-box.
- Publishes separate rule sets by routing policy:
  - `proxy.srs` — PROXY rules from lazy.conf
  - `direct.srs` — DIRECT rules from lazy.conf
  - `reject.srs` — REJECT rules if present
- The workflow also keeps `source/` JSON files for inspection.

## Karing URLs

After the repository is made **Public**, use:

`https://raw.githubusercontent.com/libraprince/Karingset/main/srs/proxy.srs`

`https://raw.githubusercontent.com/libraprince/Karingset/main/srs/direct.srs`

`https://raw.githubusercontent.com/libraprince/Karingset/main/srs/reject.srs`

Recommended Karing routing order:

1. LAN → DIRECT
2. China / China Apps → DIRECT
3. `direct.srs` → DIRECT
4. `proxy.srs` → PROXY
5. `reject.srs` → REJECT
6. FINAL → PROXY

For China IP matching, use Karing's `ChinaIp.srs` rather than trying to convert Shadowrocket's `GEOIP,CN` line into a domain rule set.

## Update

GitHub Actions runs daily and can also be started manually from Actions → `Build Karing SRS`.
