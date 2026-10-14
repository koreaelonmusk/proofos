# ProofOS · Independent Evidence Console UX Plan

**Scope:** ProofOS only. Baseline `main@5b703141274b695c354ec15e1f89318753b99238`. Design specification, not a product code patch.

## Brand promise

**AI agents execute. ProofOS proves.** Keep the existing differentiated message and verified-demo material. Do not import Extropy AI OS themes or its Council workflow.

## Audit-first user journey

1. **Verdict first:** VERIFIED / ABSTAIN + reason, verification time, observer independence. Never label unchecked agent prose `verified`.
2. **Trace in one click:** execution ID → collector identity → signed observation → independent verifier result → append-only journal checkpoint.
3. **Failure transparency:** missing evidence, bad signature, stale trust root, compromised verifier and replay attempts must have distinct visible outcomes.
4. **Independent provenance:** display source SHA, deployment revision, signed payload hash and verifier decision without hiding uncertainty behind color.
5. **Comparison UX:** compare refused claim and subsequent accepted independent observation side-by-side, with their evidence boundaries.
6. **Public vs private surfaces:** demo must use sanitized prerecorded proof, not imply live API connectivity or allow arbitrary internal record access.
7. **Commercial trust:** auditors need exportable proof bundles and reproducible verification commands before polished marketing metrics.
8. **Accessibility:** contrast never sole verdict indicator, keyboard-accessible timeline, explain acronym on first use, clear terminal vs proposed status.

## Roadmap

- **P0:** validate existing public evidence console and `artifacts/` links at exact deployed SHA; preserve current live-demo truth labels.
- **P1:** evidence provenance navigation, event timeline, signed bundle download and deterministic verify instruction surfaces.
- **P2:** adversarial test failure explanations and independent trust-root rotation status.
- **P3:** enterprise onboarding case study, security questionnaire, immutable evidence API and benchmark methodology.
- **P4:** only merge after verifier unit tests, CI, CLI output and public browser E2E pass.

## Success metrics

Auditor time-to-first-valid-proof, claim rejection correctness, reproducibility across clean machines, provenance completeness, and zero false VERIFIED. Never claim performance from decorative badges.

This is one portfolio product's UX roadmap, not a replacement for existing code or a deployment.