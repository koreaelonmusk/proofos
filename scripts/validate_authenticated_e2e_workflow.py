"""Validate the authenticated E2E workflow's identity and launch-gate contract."""

from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/authenticated-e2e.yml"

REQUIRED_SNIPPETS = (
    "actions: read",
    "id-token: write",
    "live_evidence_run_id:",
    "uses: actions/download-artifact@v7",
    "uv run python scripts/authorize_authenticated_e2e.py",
    "uses: google-github-actions/auth@v3",
    "workload_identity_provider: ${{ secrets.PROOFOS_E2E_GCP_WIF_PROVIDER }}",
    "service_account: ${{ secrets.PROOFOS_E2E_GCP_SERVICE_ACCOUNT }}",
    "token_format: id_token",
    "id_token_audience: ${{ inputs.deployment_url }}",
    "id_token_include_email: true",
    "create_credentials_file: false",
    "export_environment_variables: false",
    "PROOFOS_E2E_CALLER_ID_TOKEN: ${{ steps.google-auth.outputs.id_token }}",
    "VERCEL_AUTOMATION_BYPASS_SECRET: ${{ secrets.VERCEL_AUTOMATION_BYPASS_SECRET }}",
)
FORBIDDEN_SNIPPETS = (
    "secrets.PROOFOS_E2E_CALLER_ID_TOKEN",
    "credentials_json:",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "ref: ${{ inputs.expected_git_sha }}",
)


def validate() -> list[str]:
    issues: list[str] = []
    if not WORKFLOW.exists():
        return ["authenticated_e2e_workflow_missing"]

    text = WORKFLOW.read_text(encoding="utf-8")
    for snippet in REQUIRED_SNIPPETS:
        if snippet not in text:
            issues.append("missing:" + snippet)
    for snippet in FORBIDDEN_SNIPPETS:
        if snippet in text:
            issues.append("forbidden:" + snippet)

    if text.count("uses: google-github-actions/auth@v3") != 1:
        issues.append("google_auth_action_must_appear_exactly_once")

    checkout = text.find("uses: actions/checkout@v7")
    gate = text.find("- name: Authorize privileged authenticated E2E")
    auth = text.find("uses: google-github-actions/auth@v3")
    collect = text.find("uv run python scripts/verify_authenticated_collection.py \\")

    if checkout < 0 or gate < 0 or auth < 0 or collect < 0:
        issues.append("required_workflow_stage_missing")
    elif not (checkout < gate < auth < collect):
        issues.append("launch_gate_must_precede_google_identity_and_collection")

    source_check = text.find("Verify source evidence workflow identity")
    download = text.find("Download sealed health evidence")
    if source_check < 0 or download < 0 or gate < 0 or not (source_check < download < gate):
        issues.append("source_workflow_and_artifacts_must_precede_launch_gate")

    return issues


def main() -> int:
    issues = validate()
    if issues:
        print("Authenticated E2E workflow contract FAILED")
        for issue in issues:
            print(f"- {issue}")
        return 1

    print("Authenticated E2E workflow contract OK")
    print("- sealed launch verdict: required before credentials")
    print("- source workflow identity: verified")
    print("- source Git SHA: verified")
    print("- GitHub OIDC permission: required")
    print("- Google WIF ID token: minted only after READY authorization")
    print("- stored caller token secret: forbidden")
    print("- Vercel edge bypass: secret request header only")
    return 0


if __name__ == "__main__":
    sys.exit(main())
