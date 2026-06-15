# Trust-zone routing reference

## Invariants

1. Raw health documents and direct identifiers remain in `private_ingest`.
2. `public_research` receives only a de-identified question and writes only
   public-source artifacts.
3. `source_review` is a fresh public-only task with live WebSearch. It receives
   only a de-identified question and public IDs/URLs, inspects source content,
   and cannot register, review, or issue claims.
4. `offline_synthesis` calls `load_synthesis_packets` with one issued ID of each
   kind and receives the bounded canonical CasePacket and EvidencePacket; it
   does not retrieve sources or accept replacement packet JSON.
5. `audit` is a read-only, no-network runtime zone. It receives a public answer
   plus an issued `EvidencePacket` ID, can load that one bounded canonical
   packet for inspection, reads only the public handoff, and cannot retrieve,
   write packets, or access case/private material.
6. `review_export` is a logical stage that requires operator review before any
   user-facing export; it is not a separately enforced MCP zone.
7. A hook, prompt, custom-agent name, or packet schema is defense in depth, not
   a trust boundary. Seatbelt wrappers constrain MCP child processes, but a root
   Codex task can receive subagent outputs in shared context.
8. Private, synthesis, and audit MCP entry points are stdio-only. All shipped
   wrappers pin stdio.
9. Custom-agent shells read explicit runtime/code/docs paths, not the project
   root; `state`, private/staging/output paths, `.env`, and `.git` remain denied.
10. Every named agent disables the plugin-provided full public MCP and uses only
    its explicit zone MCP allowlist. Public agents may retain the plugin's
    reviewed skills and DLP hook; those do not widen their MCP tool surface.

## Artifact flow

```text
private source -> issued CasePacket (verified subset) --------+
                                                                +-> offline AnswerBundle -> synthesis audit
de-identified question -> metadata discovery                    |
                      -> fresh source review                     |
                      -> reviewed claim issuance/EvidencePacket -+-------------> public audit
                                                                                  |
                                                                                  v
                                                                            review_export
```

An EvidencePacket 1.3 separates bibliographic `items` from verified
`reviewed_claims`. Metadata item IDs cannot support substantive claims. Study
claims require registered candidates, exact confirmation, and review receipts;
guideline registry HMACs provide local integrity only and are not source review.
Guideline claims require resolved recommendation IDs, per-recommendation
candidate registration, exact separate-review confirmation of wording, native grade,
provenance, limitations, source root, and semantic item snapshot, and packet
issuance with review receipts that exactly cover those IDs. The semantic item
snapshot excludes only `retrieved_at`.
The registry is a lazy cache, not a mirrored guideline library. Call
`plan_guidance_discovery` before live inspection; cache only selected documents
used for personal-context or clinical-action answers. Informational answers may
remain live-cited without registry import.
The dedicated audit MCP exposes a bounded public-packet loader and a structural
public-claim check; synthesis checks complete case-plus-evidence bundles.
Neither path proves that a source semantically entails a reviewed claim.
Locally, private/public issuers write separate packet stores;
synthesis loads both stores read-only and audit loads only the public store.
Packet-kind-specific HMAC keys outside SQLite bind kind, ID, and canonical
payload hash. This is not encryption, a cross-zone signature, remote
attestation, or a hard boundary from another process under the same OS account.
For strict separation, run the roles in separate tasks/processes or OS
identities and use an authenticated minimal-packet handoff.

## Minimum routing record

```json
{
  "decision": "public_research",
  "reason": "Current guideline evidence is required",
  "allowed_inputs": ["de-identified question"],
  "prohibited_inputs": ["CasePacket", "identifiers", "local paths"],
  "next_skill": "retrieve-scientific-evidence",
  "expected_artifact": "EvidencePacket",
  "verification_gate": "metadata identity checked; substantive support requires a reviewed claim receipt",
  "stop_conditions": ["input contains private data"]
}
```
