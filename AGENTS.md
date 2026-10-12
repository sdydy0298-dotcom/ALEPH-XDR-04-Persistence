# ALEPH XDR-04 · Persistence defense
- Work ONLY in `sdydy0298-dotcom/ALEPH-XDR-04-Persistence`. Do not modify XDR-01/02/03.
- The official `xdr/fixtures/persistence.json` (24 original training alerts) must stay byte-for-byte unchanged.
- The upstream `scripts/xdr-run.mjs` must remain unchanged and emit `aleph.xdr.result.v1`.
- `xdr/persistence/decide.mjs` must be self-contained, deterministic and `export function decide(alert)` with no imports, filesystem, network or external dependencies.
- Threshold contract: confidence >= 0.85 block; >= 0.50 alert; otherwise record. Only corroborated persistence creates isolation candidates.
- `respond.mjs` owns notifications and the 15-minute expiring file-based ZTNA deny candidates; original `ztna/rules.json` is read only.
- Never output or commit real credentials, access tokens, cookies, authorization headers, raw event bodies, or system secrets.
- Public Vercel page is a static educational simulation; no real Wazuh or enterprise ZTNA enforcement is claimed.
- Run: `npm run xdr:run -- persistence`, `npm test`, `npm run build`, and verify no generated-file diffs.
