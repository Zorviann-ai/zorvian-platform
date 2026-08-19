# Zorvian Gate 5 — Core-Connected Beta

## Objective
Move the controlled Gate 4 HTMLs from local-only specialist logic to authenticated, tenant-isolated, auditable calls into Zorvian Core while preserving Guardian controls and human approval boundaries.

## Rules
- No public anonymous execution against production business data.
- Every connected request carries authenticated user, tenant and module context.
- Every request is routed through the Gate 3 Intelligence Router before provider/tool selection.
- Consequential actions remain blocked pending explicit approval.
- Provider credentials remain server-side only.
- Beta modules may analyse, retrieve approved workspace context and draft outputs; they may not silently execute external actions.
- Provenance, confidence and audit metadata are returned with every intelligence response.

## First connected capabilities
1. Receptionist analysis and hand-off drafting
2. ZAI Auto requirement analysis and vehicle-route recommendation
3. FreshX opportunity analysis
4. Tender requirement analysis and response planning
5. Lead prioritisation
6. Document drafting
7. Business Control prioritisation
8. Route planning requirements analysis

## Gate 5 completion criteria
- authenticated API endpoint for intelligence requests
- tenant context envelope enforced
- provider-neutral adapter boundary
- approval/risk decision returned
- provenance/confidence returned
- audit event written for every request
- no provider secret exposed to browser
- tests for authentication, tenant separation, unsupported module, approval gating and provider failure
- connected beta JavaScript uses only the Zorvian Core endpoint
