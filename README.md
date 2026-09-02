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

## Karing one-file diversion preset

Use this preset to add the three policy rule sets at once:

`https://raw.githubusercontent.com/libraprince/Karingset/main/karing/Karingset-Diversion.json`

It contains:

- `reject.srs` → BLOCK
- `direct.srs` → DIRECT
- `proxy.srs` → CURRENT SELECTED

The three `.srs` files remain remote resources, so Karing can update them independently without rebuilding the preset. Karing supports remote `.srs` / `.json` Rule Sets.

## Direct Rule Set URLs

`https://raw.githubusercontent.com/libraprince/Karingset/main/srs/proxy.srs`

`https://raw.githubusercontent.com/libraprince/Karingset/main/srs/direct.srs`

`https://raw.githubusercontent.com/libraprince/Karingset/main/srs/reject.srs`

## Important

Karing currently does not support a `rule-set=` parameter in `karing://install-config`. That feature has been proposed upstream but is not currently available. Therefore the recommended one-file entry is the Karing diversion JSON preset above rather than a fake `karing://` link.

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

GitHub Actions runs daily and can also be started manually from Actions → `Build Karing SRS`.
