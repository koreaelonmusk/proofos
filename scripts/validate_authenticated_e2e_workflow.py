"""Validate the authenticated E2E workflow's short-lived identity contract."""

from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/authenticated-e2e.yml"

REQUIRED_SNIPPETS = (
    "id-token: write",
    "uses: google-github-actions/auth@v3",
    "workload_identity_provider: ${{ secrets.PROOFOS_E2E_GCP_WIF_PROVIDER }}",
    "service_account: ${{ secrets.PROOFOS_E2E_GCP_SERVICE_ACCOUNT }}",
    "token_format: id_token",
    "id_token_audience: ${{ inputs.deployment_url }}",
    "id_token_include_email: true",
    "create_credentials_file: false",
    "export_environment_variables: false",
    "PROOFOS_E2E_CALLER_ID_TOKEN: ${{ steps.google-auth.outputs.id_token }}",
)
FORBIDDEN_SNIPPETS = (
    "secrets.PROOFOS_E2E_CALLER_ID_TOKEN",
    "credentials_json:",
    "GOOGLE_APPLICATION_CREDENTIALS",
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
    auth = text.find("uses: google-github-actions/auth@v3")
    if checkout < 0 or auth < 0 or checkout > auth:
        issues.append("checkout_must_precede_google_auth")

    return issues


def main() -> int:
    issues = validate()
    if issues:
        print("Authenticated E2E identity contract FAILED")
        for issue in issues:
            print(f"- {issue}")
        return 1

    print("Authenticated E2E identity contract OK")
    print("- GitHub OIDC permission: required")
    print("- Google WIF auth action: v3")
    print("- caller ID token: minted at run time")
    print("- stored caller token secret: forbidden")
    print("- ID token audience: exact deployment input")
    print("- service-account email claim: required")
    return 0


if __name__ == "__main__":
    sys.exit(main())
