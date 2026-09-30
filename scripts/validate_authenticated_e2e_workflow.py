"""Validate the authenticated E2E workflow's two-job authority contract."""

from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/authenticated-e2e.yml"

GLOBAL_REQUIRED = (
    "permissions: {}",
    'workflows: ["Vercel Live Smoke Evidence"]',
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
    "VERCEL_AUTOMATION_BYPASS_SECRET: ${{ secrets.VERCEL_AUTOMATION_BYPASS_SECRET }}",
    "verify_authenticated_e2e_promotion.py",
)
FORBIDDEN_GLOBAL = (
    "secrets.PROOFOS_E2E_CALLER_ID_TOKEN",
    "credentials_json:",
    "GOOGLE_APPLICATION_CREDENTIALS",
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
        "AUTO_RUN_ID: ${{ github.event.workflow_run.id }}",
        "AUTO_GIT_SHA: ${{ github.event.workflow_run.head_sha }}",
        "MANUAL_RUN_ID: ${{ inputs.live_evidence_run_id }}",
        "test \"$(gh api \"$api\" --jq '.head_branch')\" = \"main\"",

        "Verify source evidence workflow identity",
        "Download sealed health evidence",
        "Download sealed trust evidence",
        "Download sealed evidence manifest",
        "Download sealed launch verdict",
        "- name: Authorize privileged authenticated E2E",
        "uv run python scripts/authorize_authenticated_e2e.py",
        "authorized: ${{ steps.authorize.outputs.authorized }}",
        "target_origin: ${{ steps.authorize.outputs.target_origin }}",
        "source_git_sha: ${{ steps.authorize.outputs.source_git_sha }}",
        'echo "authorized=$authorized" >> "$GITHUB_OUTPUT"',
    )
    for snippet in required_authorize:
        if snippet not in authorize:
            issues.append("authorization_job_missing:" + snippet)

    for snippet in PRIVILEGED_REQUIRED:
        if snippet not in privileged:
            issues.append("privileged_job_missing:" + snippet)

    if text.count("id-token: write") != 1:
        issues.append("oidc_permission_must_exist_exactly_once")
    if text.count("uses: google-github-actions/auth@v3") != 1:
        issues.append("google_auth_action_must_appear_exactly_once")
    if text.count('workflows: ["Vercel Live Smoke Evidence"]') != 1:
        issues.append("live_smoke_workflow_trigger_must_appear_exactly_once")
    if 'test "$(jq -r '.authorized' <<<"$result")" = "true"' in authorize:
        issues.append("hold_must_not_fail_authorization_job")

    gate = authorize.find("- name: Authorize privileged authenticated E2E")
    source = authorize.find("Verify source evidence workflow identity")
    download = authorize.find("Download sealed health evidence")
    if min(gate, source, download) < 0 or not (source < download < gate):
        issues.append("source_identity_and_bundle_must_precede_authorization")

    auth = privileged.find("uses: google-github-actions/auth@v3")
    collect = privileged.find("- name: Collect fresh authenticated signed evidence")
    promotion = privileged.find("- name: Cross-check authenticated evidence against sealed launch bundle")
    if min(auth, collect, promotion) < 0 or not (auth < collect < promotion):
        issues.append("oidc_then_collection_then_promotion_order_required")

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
    print("- privileged job: created only after READY authorization")
    print("- GitHub OIDC/WIF: short-lived identity only in privileged job")
    print("- stored caller token and service-account JSON: forbidden")
    print("- automatic trigger: successful main-branch live evidence only")
    print("- HOLD: safe green authorization result; privileged job stays skipped")
    print("- authenticated collection: cross-checked against sealed launch bundle")
    return 0


if __name__ == "__main__":
    sys.exit(main())
