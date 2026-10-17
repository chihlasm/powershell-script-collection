# Owner decisions

Every answer the owner gives during planning or review lands here, so the squad never
asks the same thing twice and later items inherit earlier choices. Agents read this
before asking anything. Newest entries at the bottom.

Format: `- D-### (YYYY-MM-DD, SQ-###): Question -> Answer. Applies to: <scope>.`

---

- D-001 (2026-10-17, SQ-002): What share of clients have Entra ID P1? -> About half. The tool must treat "no sign-in logs" as a normal path with a useful non-P1 verdict. Applies to: SQ-002 and any later Entra/M365 tool.
- D-002 (2026-10-17, SQ-002): Which account do techs use in client tenants? -> Often the client's global admin account, because it's easier for admin tasks. Tools must stay read-only whatever the account's rights and must show the tenant and signed-in account first. Applies to: all M365/Entra tools.
- D-003 (2026-10-17, SQ-002): Does the MSP run CIPP? -> "Fairly certain" yes, though techs often work directly as the client's global admin. Applies to: mailbox/takeover and per-user cloud checks.