# Zorvian Gate 3 — Intelligence Foundation

## Objective
Turn Zorvian Core from a collection of business modules into a governed, model-independent business intelligence operating system.

## Intelligence architecture
1. **Zorvian Core** — identity, tenant isolation, permissions, audit and business state.
2. **Guardian** — security policy, risk controls, privacy boundaries and approval gates.
3. **Intelligence Router** — selects the appropriate model/tool strategy for each task. Providers are replaceable; Zorvian owns orchestration.
4. **Workspace Context** — company-specific instructions, approved knowledge, terminology, preferences and operational history.
5. **Specialist Agents** — bounded agents operating through the same Core and permission system.
6. **Action Engine** — tools and integrations execute approved actions; sensitive actions require explicit approval.
7. **Evidence & Provenance** — important outputs record sources, confidence, assumptions and action history.
8. **Evaluation Layer** — regression tests and human beta scoring measure quality rather than assuming intelligence.

## Gate 3 specialist modules
- AI Receptionist
- ZAI Auto (Zorvian Auto Intelligence)
- FreshX
- Contract & Tender Intelligence
- Lead Intelligence
- Document Studio
- Business Control
- Route Intelligence

### ZAI Auto
Public automotive product name: **Zorvian Auto Intelligence (ZAI Auto)**.

Club 1 Leasing may retain **Little Sis** as its private named agent/persona. Little Sis is not the platform product name.

ZAI Auto scope:
- vehicle sourcing and stock matching
- customer qualification and structured fact-find
- PCH/BCH/PCP and salary-sacrifice support
- EV/BIK comparison support
- quotation preparation
- lead follow-up and appointment handling
- dealer/funder communication workflows
- compliance prompts and approval controls
- document collection
- CRM progression
- future automotive data integrations behind permissioned adapters

## Human approval boundary
AI may research, analyse, draft, compare, recommend and prepare actions. External communication, contractual commitment, financial commitment, destructive actions, permission changes and other high-impact actions must pass policy/role checks and, where configured, human approval.

## Beta programme
Each public beta component must have:
- approved Zorvian black/gold presentation
- realistic test scenarios
- no production credentials or secrets
- bounded demo data/workspace
- visible beta status
- structured feedback capture
- usefulness, accuracy, clarity and speed scoring
- missing-feature feedback
- willingness-to-use / willingness-to-pay signal

A central Beta Test Hub will route testers to individual component experiences and feedback.

## Gate 3 quality bar
Gate 3 is not complete because an LLM answers prompts. Completion requires measurable tests for:
- tenant isolation
- authentication/authorisation
- prompt-injection resistance at tool boundaries
- correct tool/module selection
- hallucination resistance
- evidence/provenance handling
- approval enforcement
- cross-module context handling
- specialist-domain task quality
- graceful provider/tool failure
- auditability

## Delivery discipline
Gate 3 changes are developed on `gate3-intelligence-foundation`, tested there, reviewed through a pull request, and only promoted to `main` after the gate passes. Production Core remains protected during development.
