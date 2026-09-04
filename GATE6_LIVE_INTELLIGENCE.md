# Gate 6 — Live Intelligence & Model Federation

## Principle
Zorvian is the intelligence operating mechanism. External models are replaceable server-side capability engines. Business modules never depend directly on a provider.

## Gate 6 requirements
- provider-neutral federation policy
- quality-first model selection by capability
- independent second-provider verification for high-stakes tasks where available
- provider failure closes safely rather than fabricating output
- provider credentials remain server-side
- no provider branding or provider-specific contract in specialist modules
- evaluation data can alter routing without rewriting modules
- Zorvian Core/Guardian permissions remain authoritative
- provenance records which provider class produced and verified an answer without exposing secrets
- local/self-hosted adapters can participate in the same federation contract

## Capability classes
Reasoning, documents, retrieval, vision, multilingual, structured extraction, coding, communications and specialist-domain analysis can be routed independently.

## High-stakes policy
Legal, contractual, compliance, financial commitment, healthcare, destructive operations, permissions changes and other consequential tasks remain human-review/approval bounded. Model agreement does not replace human authority.

## Provider strategy
Gate 6 deliberately does not hard-code one commercial provider. Production adapters are configured server-side. A provider can be introduced, removed or replaced without rewriting ZAI Auto, FreshX, Tenders, Receptionist or the other Zorvian specialist modules.

## Completion evidence
Gate 6 CI must prove selection, fallback/failure behaviour, independent verification, disabled-provider exclusion and regression compatibility with Gates 2–5 before promotion to main.
