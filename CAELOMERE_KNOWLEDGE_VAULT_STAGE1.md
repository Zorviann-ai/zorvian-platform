# Caelomere Knowledge Vault — Stage 1

## Knowledge Vault purpose

The Vault is a governed knowledge-ingestion foundation so Celeste can use trusted, current, source-backed industry knowledge for different client types.

Celeste must **not** answer professional or compliance-heavy queries from generic model memory alone.

Flow:

```
Client business type
→ Industry Pack
→ jurisdiction
→ approved source
→ current version
→ retrieval
→ Celeste answer
→ provenance / evidence
→ professional-review flag where required
```

## Industry Packs

Initial packs (jurisdiction is explicit and not UK-identical):

| Pack ID | Industry | Jurisdiction |
|---|---|---|
| `CONSTRUCTION_UK` | construction | England (HSE sources often Great Britain) |
| `LEGAL_ENGLAND_WALES` | legal | England and Wales |
| `PROPERTY_ENGLAND` | property / landlord | England |
| `EDUCATION_UK` | education | England (WJEC catalogued as Wales) |

Later extensible to finance, motor, healthcare, hospitality, retail and other industries. Packs must stay nation-specific.

## Source validation

Stage 1 uses an allowlist of official domains only:

- legislation.gov.uk
- gov.uk
- hse.gov.uk
- sra.org.uk (metadata / link only)
- aqa.org.uk, qualifications.pearson.com, ocr.org.uk, wjec.co.uk, eduqas.co.uk (metadata / link only)

Unofficial domains are rejected. There is no uncontrolled crawl.

Pipeline:

`DISCOVER → VALIDATE SOURCE → CHECK RIGHTS → FETCH / IMPORT → NORMALISE → SPLIT → METADATA → HASH → VERSION → INDEX → AUDIT`

## Jurisdiction control

Every record and pack stores a jurisdiction string. Retrieval keeps the pack jurisdiction. A requested nation that does not match the pack is flagged; it is not silently rewritten as “UK”.

## Legal-status classification

`legal_status` is one of:

- `PRIMARY_LAW`
- `SECONDARY_LEGISLATION`
- `STATUTORY_GUIDANCE`
- `REGULATOR_RULE`
- `OFFICIAL_GUIDANCE`
- `CURRICULUM_SPECIFICATION`
- `LOCAL_PROCEDURE`
- `OTHER`

## Provenance

Professional / compliance-heavy answers can return:

- source authority
- source title
- jurisdiction
- version / effective date
- source URL
- confidence state
- professional-review requirement

Sentence form:

> This answer is based on [official source], applies to [jurisdiction], and was last verified on [date].

## Confidence states

- **GREEN / VERIFIED** — current approved authoritative source with ingested body supports the answer.
- **AMBER / ADVISORY** — relevant catalogued source exists but facts, context, jurisdiction or interpretation need checking (including metadata-only records).
- **RED / PROFESSIONAL_REVIEW_REQUIRED** — Celeste may research and prepare information; a qualified human/professional decision is required.

These are not legal guarantees.

## Licensing boundary

- GOV.UK, legislation.gov.uk and HSE material is typically Crown copyright under the Open Government Licence v3.0. Page-level footers must still be checked before any later body ingest.
- SRA Standards & Regulations and related pages are SRA copyright. Stage 1 stores **metadata and URLs only**.
- AQA, Pearson Edexcel, OCR, WJEC and Eduqas specifications are exam-board copyright. Stage 1 stores **metadata and URLs only**.
- No commercial textbooks. No paid databases. No scraping of restricted content.

## Update / staleness control

Every record supports:

- last checked date
- current version
- content hash
- superseded flag
- stale flag
- revalidation requirement

If a source cannot be verified current, it is marked `STALE` or `REVIEW_REQUIRED`. It is not silently treated as current law or guidance.

## Client routing

| Business type | Pack |
|---|---|
| solicitor / lawyer / legal / law firm | `LEGAL_ENGLAND_WALES` |
| builder / contractor / construction / site manager | `CONSTRUCTION_UK` |
| landlord / property manager / letting agent / property | `PROPERTY_ENGLAND` |
| school / tutor / teacher / education / academy | `EDUCATION_UK` |

One Celeste. One Core. Different governed packs. Cross-pack contamination is blocked.

## Professional-review rules

Packs carry explicit review rules (for example asbestos and CDM dutyholder decisions; SRA-reliant legal advice; possession / HMO / fire-risk; safeguarding). Decision-like queries force **RED**.

## Execution boundary

Knowledge retrieval is **READ / ANALYSE / PROPOSE only**.

This stage does **not**:

- modify Stage 4G private execution flow
- call `_claimed_production_submit`
- create another `/live` path
- publish externally
- execute legal, financial or construction decisions
- scrape paid databases
- ingest copyrighted commercial textbooks without licence
- deploy
- merge
- activate production providers

## Existing foundations inspected

- Repository: `Zorviann-ai/zorvian-platform`
- Development base used: `main` after Stage 4G merge (`core/controlled-execution-gateway-phase3-stage4g`)
- Capability governance: `intelligence/legal.py`, `intelligence/guardian.py`, `intelligence/financial.py`, `intelligence/orchestrator.py`
- Education surface already present in the product layer: `src/curriculum.js`, `src/tutor.js`
- Website Guardian / Sovereign Reserve work exists as branch `core/website-guardian-sovereign-reserve-stage1` and was not modified here
- Stage 4G execution protection tests remain the authority for `/live` and `_claimed_production_submit`

---

THIS STAGE DOES NOT GUARANTEE PROFESSIONAL ADVICE.

THIS STAGE DOES NOT INGEST PAID OR RESTRICTED CONTENT WITHOUT LICENCE.

THIS STAGE DOES NOT EXECUTE PROFESSIONAL DECISIONS.

THIS STAGE DOES NOT DEPLOY TO PRODUCTION.
