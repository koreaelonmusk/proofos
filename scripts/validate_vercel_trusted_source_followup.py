"""Validate the Vercel Trusted Source follow-up workflow authority boundary."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/vercel-trusted-source-followup.yml"


def validate() -> list[str]:
    issues: list[str] = []
    if not WORKFLOW.exists():
        return ["trusted_source_followup_workflow_missing"]

    text = WORKFLOW.read_text(encoding="utf-8")

    required_global = (
        'workflows: ["Vercel Live Smoke Evidence"]',
        "types: [completed]",
        "permissions: {}",
        "authorize:",
        "trusted-source:",
    )
    for snippet in required_global:
        if snippet not in text:
            issues.append("missing:" + snippet)

    auth_marker = "\n  authorize:\n"
    trusted_marker = "\n  trusted-source:\n"
    a = text.find(auth_marker)
    t = text.find(trusted_marker)
    if a < 0 or t < 0 or a >= t:
        issues.append("authorize_and_trusted_jobs_must_be_separate")
        return issues

    authorize = text[a:t]
    trusted = text[t:]

    required_authorize = (
        "github.event.workflow_run.conclusion == 'success'",
        "github.event.workflow_run.head_branch == 'main'",
        "contents: read",
        "actions: read",
        "SOURCE_RUN_ID: ${{ github.event.workflow_run.id }}",
        "SOURCE_GIT_SHA: ${{ github.event.workflow_run.head_sha }}",
        "Verify source live-evidence workflow identity",
        "test \"$(gh api \"$api\" --jq '.name')\" = \"Vercel Live Smoke Evidence\"",
        "test \"$(gh api \"$api\" --jq '.event')\" = \"deployment_status\"",
        "test \"$(gh api \"$api\" --jq '.conclusion')\" = \"success\"",
        "test \"$(gh api \"$api\" --jq '.head_branch')\" = \"main\"",
        "download_run_artifact.py",
        "verify_live_launch_verdict.py",
        "test \"$(jq -r '.deployment_environment' \"$verdict\")\" = \"production\"",
    )
    for snippet in required_authorize:
        if snippet not in authorize:
            issues.append("authorize_missing:" + snippet)

    if "id-token: write" in authorize:
        issues.append("authorize_job_must_not_have_oidc_authority")
    if "${{ secrets." in authorize:
        issues.append("authorize_job_must_not_reference_secrets")
    if "core.getIDToken" in authorize:
        issues.append("authorize_job_must_not_mint_oidc")

    required_trusted = (
        "needs: authorize",
        "actions: read",
        "id-token: write",
        "- name: Install minimal verifier runtime",
        "uv sync --locked",
        "uv run python scripts/download_run_artifact.py",
        "Mint short-lived GitHub OIDC identity from main follow-up",
        "uses: actions/github-script@v7",
        "const token = await core.getIDToken();",
        "core.setSecret(token);",
        "VERCEL_TRUSTED_OIDC_TOKEN: ${{ steps.oidc.outputs.token }}",
        "needs.authorize.outputs.target_origin",
        "needs.authorize.outputs.source_git_sha",
        "needs.authorize.outputs.github_deployment_id",
        "needs.authorize.outputs.github_deployment_status_id",
        "verify_vercel_trusted_source.py",
        "verify_vercel_trusted_source_artifact.py",
        "build_vercel_trusted_source_diagnosis.py",
        '--source-run-id "$SOURCE_RUN_ID"',
        '--followup-run-id "$GITHUB_RUN_ID"',
        "verify_vercel_trusted_source_diagnosis.py",
        "Build and independently verify Provider Admission Contract",
        "build_vercel_provider_admission.py",
        "verify_vercel_provider_admission.py",
        "vercel-trusted-diagnosis-",
        "vercel-provider-admission-",
        "archive: false",
    )
    for snippet in required_trusted:
        if snippet not in trusted:
            issues.append("trusted_missing:" + snippet)

    if text.count("id-token: write") != 1:
        issues.append("oidc_permission_must_exist_exactly_once")
    if text.count("core.getIDToken()") != 1:
        issues.append("oidc_token_must_be_minted_exactly_once")
    if "VERCEL_AUTOMATION_BYPASS_SECRET" in text:
        issues.append("static_vercel_bypass_secret_forbidden")
    if "x-vercel-protection-bypass" in text:
        issues.append("static_vercel_bypass_header_forbidden")
    if "echo ${{ steps.oidc.outputs.token }}" in text:
        issues.append("oidc_token_must_not_be_printed")

    return issues


def main() -> int:
    issues = validate()
    if issues:
        print("Vercel trusted-source follow-up workflow contract FAILED")
        for issue in issues:
            print(f"- {issue}")
        return 1

    print("Vercel trusted-source follow-up workflow contract OK")
    print("- source run: completed successful main live-evidence workflow only")
    print("- authorization job: artifact verification only, no OIDC, no secrets")
    print("- trusted job: sole short-lived OIDC authority + run-scoped provider diagnosis")
    print("- static Vercel bypass authority: forbidden")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
