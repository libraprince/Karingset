# Karingset

Karing / sing-box Rule Set generator based on Johnshall Shadowrocket `lazy.conf`.

## What it does

- Pulls the current Johnshall `lazy.conf` twice a day.
- Downloads the referenced RULE-SET lists from their upstream sources.
- Converts supported domain / IP rules into sing-box source JSON.
- Compiles the JSON into `.srs` with sing-box 1.14.0.
- Publishes separate rule sets by routing policy:
  - `proxy.srs` — PROXY rules from lazy.conf
  - `direct.srs` — DIRECT rules from lazy.conf
  - `reject.srs` — REJECT rules if present
- Keeps `source/` JSON files and `source/manifest.json` for inspection.
- Runs parser regression tests before every generated build.

## Karing one-file diversion presets

### Full service preset

Use this preset when you want service-level routing such as OpenAI, Claude, Gemini, GitHub, X, YouTube, Telegram, Netflix and gaming services:

`https://raw.githubusercontent.com/libraprince/Karingset/main/karing/Karingset-All.json`

The preset contains remote `.srs` URLs, so the preset itself does not need to be replaced when the rule contents update.

### Policy preset

Use this smaller preset if you only want the three policy rule sets:

`https://raw.githubusercontent.com/libraprince/Karingset/main/karing/Karingset-Diversion.json`

It contains:

- `reject.srs` → BLOCK
- `direct.srs` → DIRECT
- `proxy.srs` → CURRENT SELECTED

Karing supports remote `.srs` / `.json` Rule Sets.

## Direct Rule Set URLs

`https://raw.githubusercontent.com/libraprince/Karingset/main/srs/proxy.srs`

`https://raw.githubusercontent.com/libraprince/Karingset/main/srs/direct.srs`

`https://raw.githubusercontent.com/libraprince/Karingset/main/srs/reject.srs`

## Important

Karing currently does not support a `rule-set=` parameter in `karing://install-config`. Therefore the recommended one-file entry is the Karing diversion JSON preset rather than a fake `karing://` link.

For a complete proxy configuration, import your normal subscription first, then import/apply the Karingset diversion preset. The preset does not contain proxy nodes.

Recommended Karing routing order:

1. LAN → DIRECT
2. China / China Apps → DIRECT
3. `reject.srs` → BLOCK
4. `direct.srs` → DIRECT
5. `proxy.srs` → CURRENT SELECTED
6. FINAL → according to your Karing default

For China IP matching, use Karing's `ChinaIp.srs` rather than trying to convert Shadowrocket's `GEOIP,CN` line into a domain rule set.

## Update

GitHub Actions runs automatically at 08:15 and 20:15 Beijing time, and can also be started manually from Actions → `Build Karing SRS`.

The build toolchain is pinned to Python 3.13 and sing-box 1.14.0 for reproducible compilation. Upstream download failures fail the build instead of publishing a partial rule set.
