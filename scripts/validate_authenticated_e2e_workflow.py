"""Validate the authenticated E2E workflow's two-job authority contract."""

from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/authenticated-e2e.yml"

GLOBAL_REQUIRED = (
    "permissions: {}",
    'workflows: ["Vercel Trusted Source Follow-up"]',
    "types: [completed]",
    "workflow_dispatch:",
    "live_evidence_run_id:",
    "authorize:",
    "privileged-e2e:",
)
PRIVILEGED_REQUIRED = (
    "needs: authorize",
    "if: needs.authorize.outputs.authorized == 'true'",
    "id-token: write",
    "uses: google-github-actions/auth@v3",
    "workload_identity_provider: ${{ secrets.PROOFOS_E2E_GCP_WIF_PROVIDER }}",
    "service_account: ${{ secrets.PROOFOS_E2E_GCP_SERVICE_ACCOUNT }}",
    "token_format: id_token",
    "id_token_audience: ${{ needs.authorize.outputs.target_origin }}",
    "id_token_include_email: true",
    "create_credentials_file: false",
    "export_environment_variables: false",
    "PROOFOS_E2E_CALLER_ID_TOKEN: ${{ steps.google-auth.outputs.id_token }}",
    "VERCEL_TRUSTED_OIDC_TOKEN: ${{ steps.vercel-oidc.outputs.token }}",
    "uses: actions/github-script@v7",
    "const token = await core.getIDToken();",
    "core.setSecret(token);",
    "verify_authenticated_e2e_promotion.py",
    "- name: Independently rebuild authorized Trusted Promotion Proof",
    "build_trusted_promotion_proof.py",
    "verify_trusted_promotion_proof.py",
    "- name: Independently rebuild authorized Follow-up Trusted Promotion Proof",
    "build_followup_trusted_promotion.py",
    "verify_followup_trusted_promotion.py",
    "AUTHORIZED_PROMOTION_SHA: ${{ needs.authorize.outputs.trusted_promotion_sha256 }}",
    '--source-run-id "$SOURCE_RUN_ID"',
    '--followup-run-id "$FOLLOWUP_RUN_ID"',
)
FORBIDDEN_GLOBAL = (
    "secrets.PROOFOS_E2E_CALLER_ID_TOKEN",
    "credentials_json:",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "VERCEL_AUTOMATION_BYPASS_SECRET",
    "x-vercel-protection-bypass",
    "ref: ${{ inputs.expected_git_sha }}",
)


def _job_sections(text: str) -> tuple[str, str]:
    authorize_marker = "  authorize:\n"
    privileged_marker = "  privileged-e2e:\n"
    a = text.find(authorize_marker)
    p = text.find(privileged_marker)
    if a < 0 or p < 0 or a >= p:
        return "", ""
    return text[a:p], text[p:]


def validate() -> list[str]:
    issues: list[str] = []
    if not WORKFLOW.exists():
        return ["authenticated_e2e_workflow_missing"]

    text = WORKFLOW.read_text(encoding="utf-8")
    for snippet in GLOBAL_REQUIRED:
        if snippet not in text:
            issues.append("missing:" + snippet)
    for snippet in FORBIDDEN_GLOBAL:
        if snippet in text:
            issues.append("forbidden:" + snippet)

    authorize, privileged = _job_sections(text)
    if not authorize or not privileged:
        issues.append("authorization_and_privileged_jobs_must_be_separate")
        return issues

    if "id-token: write" in authorize:
        issues.append("authorization_job_must_not_have_oidc_permission")
    if "${{ secrets." in authorize:
        issues.append("authorization_job_must_not_reference_repository_secrets")
    if "google-github-actions/auth@" in authorize:
        issues.append("authorization_job_must_not_mint_google_identity")

    required_authorize = (
        "actions: read",
        "github.event.workflow_run.conclusion == 'success'",
        "github.event.workflow_run.head_branch == 'main'",
        "- name: Resolve sealed source run",
        "AUTO_FOLLOWUP_RUN_ID: ${{ github.event.workflow_run.id }}",
        "AUTO_GIT_SHA: ${{ github.event.workflow_run.head_sha }}",
        "MANUAL_RUN_ID: ${{ inputs.live_evidence_run_id }}",
        "test \"$(gh api \"$api\" --jq '.head_branch')\" = \"main\"",

        "Verify automatic provider diagnosis provenance",
        "vercel-trusted-diagnosis-",
        "vercel-trusted-followup-",
        "vercel-provider-admission-",
        "verify_vercel_trusted_source_diagnosis.py",
        "verify_vercel_provider_admission.py",
        '--followup-run-id "$FOLLOWUP_RUN_ID"',
        "followup_run_id",
        "Verify source evidence workflow identity",
        "Download sealed launch bundle with bounded retry",
        "uv run python scripts/download_run_artifact.py",
        "- name: Build trusted promotion authority when public observer is HOLD",
        "--artifact \"vercel-trusted-source-$SOURCE_RUN_ID.json\"",
        "build_trusted_promotion_proof.py",
        "verify_trusted_promotion_proof.py",
        "build_followup_trusted_promotion.py",
        "verify_followup_trusted_promotion.py",
        "- name: Authorize privileged authenticated E2E",
        "uv run python scripts/authorize_authenticated_e2e.py",
        "--trusted-source",
        "--trusted-promotion",
        "--followup-trusted-source",
        "--provider-diagnosis",
        "--provider-admission",
        "--followup-promotion",
        '--source-run-id "$SOURCE_RUN_ID"',
        "authorized: ${{ steps.authorize.outputs.authorized }}",
        "target_origin: ${{ steps.authorize.outputs.target_origin }}",
        "source_git_sha: ${{ steps.authorize.outputs.source_git_sha }}",
        "authorization_basis: ${{ steps.authorize.outputs.authorization_basis }}",
        "trusted_promotion_sha256: ${{ steps.authorize.outputs.trusted_promotion_sha256 }}",
        "Build and independently verify Trust Pipeline Receipt",
        "build_trust_pipeline_receipt.py",
        "verify_trust_pipeline_receipt.py",
        "proofos-trust-authorization-",
        "proofos-trust-pipeline-receipt-",
        'echo "authorized=$authorized" >> "$GITHUB_OUTPUT"',
    )
    for snippet in required_authorize:
        if snippet not in authorize:
            issues.append("authorization_job_missing:" + snippet)

    for snippet in PRIVILEGED_REQUIRED:
        if snippet not in privileged:
            issues.append("privileged_job_missing:" + snippet)

    for snippet in (
        "Download authorized launch bundle with bounded retry",
        "uv run python scripts/download_run_artifact.py",
    ):
        if snippet not in privileged:
            issues.append("privileged_job_missing:" + snippet)

    if text.count("id-token: write") != 1:
        issues.append("oidc_permission_must_exist_exactly_once")
    if text.count("uses: google-github-actions/auth@v3") != 1:
        issues.append("google_auth_action_must_appear_exactly_once")
    if text.count('workflows: ["Vercel Trusted Source Follow-up"]') != 1:
        issues.append("trusted_followup_workflow_trigger_must_appear_exactly_once")
    if 'workflows: ["Vercel Live Smoke Evidence"]' in text:
        issues.append("automatic_e2e_must_not_trigger_directly_from_live_smoke")
    if "test \"$(jq -r '.authorized' <<<\"$result\")\" = \"true\"" in authorize:
        issues.append("hold_must_not_fail_authorization_job")

    gate = authorize.find("- name: Authorize privileged authenticated E2E")
    source = authorize.find("Verify source evidence workflow identity")
    download = authorize.find("Download sealed launch bundle with bounded retry")
    trusted_promotion = authorize.find(
        "- name: Build trusted promotion authority when public observer is HOLD"
    )
    if min(gate, source, download, trusted_promotion) < 0 or not (
        source < download < trusted_promotion < gate
    ):
        issues.append(
            "source_bundle_and_trusted_promotion_must_precede_authorization"
        )

    rebuild = privileged.find(
        "- name: Independently rebuild authorized Trusted Promotion Proof"
    )
    followup_rebuild = privileged.find(
        "- name: Independently rebuild authorized Follow-up Trusted Promotion Proof"
    )
    edge_oidc = privileged.find("- name: Mint short-lived Vercel Trusted Source identity")
    auth = privileged.find("uses: google-github-actions/auth@v3")
    collect = privileged.find("- name: Collect fresh authenticated signed evidence")
    promotion = privileged.find("- name: Cross-check authenticated evidence against sealed launch bundle")
    if min(rebuild, followup_rebuild, edge_oidc, auth, collect, promotion) < 0 or not (
        rebuild < followup_rebuild < edge_oidc < auth < collect < promotion
    ):
        issues.append(
            "all_trusted_rebuilds_must_precede_identity_mint_and_authenticated_collection"
        )

    return issues


def main() -> int:
    issues = validate()
    if issues:
        print("Authenticated E2E workflow contract FAILED")
        for issue in issues:
            print(f"- {issue}")
        return 1

    print("Authenticated E2E workflow contract OK")
    print("- authorization job: no secrets, no OIDC permission")
    print("- sealed source run and evidence bundle: verified before authorization")
    print("- privileged job: created only after direct READY, legacy Trusted Promotion, or admitted follow-up Trusted Promotion")
    print("- Vercel edge: short-lived GitHub OIDC Trusted Source identity only")
    print("- ProofOS caller: short-lived Google WIF ID token only")
    print("- static Vercel bypass secret, stored caller token, and service-account JSON: forbidden")
    print("- automatic trigger: successful main-branch Trusted Source follow-up only")
    print("- public HOLD: promotable only from independently rebuilt legacy or Provider-Admission-backed follow-up proof")
    print("- authorization decision: sealed in an independently verified Trust Pipeline Receipt")
    print("- authenticated collection: cross-checked against sealed launch bundle")
    return 0


if __name__ == "__main__":
    sys.exit(main())
