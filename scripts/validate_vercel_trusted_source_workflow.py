"""Validate the Vercel Trusted Source probe authority boundary."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/vercel-live-smoke.yml"


def validate() -> list[str]:
    issues: list[str] = []
    text = WORKFLOW.read_text(encoding="utf-8")

    if text.count("id-token: write") != 1:
        issues.append("id_token_write_must_appear_exactly_once")

    auth_marker = "\n  trusted-source-authorize:"
    trusted_marker = "\n  trusted-source:"
    auth_start = text.find(auth_marker)
    trusted_start = text.find(trusted_marker)
    if auth_start < 0:
        issues.append("trusted_source_authorize_job_missing")
        return issues
    if trusted_start < 0 or trusted_start <= auth_start:
        issues.append("trusted_source_job_missing_or_misordered")
        return issues

    auth = text[auth_start:trusted_start]
    trusted = text[trusted_start:]

    required_auth = (
        "github.event.deployment.environment == 'Production'",
        "github.event.deployment.environment == 'production'",
        "permissions:",
        "contents: read",
        "outputs:",
        "authorized: ${{ steps.authorize.outputs.authorized }}",
        "source_git_sha: ${{ steps.authorize.outputs.source_git_sha }}",
        "deployment_url: ${{ steps.authorize.outputs.deployment_url }}",
        "ref: main",
        "fetch-depth: 0",
        "DEPLOYMENT_SHA: ${{ github.event.deployment.sha }}",
        'git fetch --no-tags origin main',
        'git cat-file -e "$sha^{commit}"',
        'git merge-base --is-ancestor "$sha" origin/main',
        'echo "authorized=true" >> "$GITHUB_OUTPUT"',
        'echo "authorized=false" >> "$GITHUB_OUTPUT"',
    )
    for snippet in required_auth:
        if snippet not in auth:
            issues.append("trusted_source_authorize_missing:" + snippet)

    if "id-token: write" in auth:
        issues.append("trusted_source_authorize_must_not_have_oidc_authority")
    if "actions/github-script" in auth or "core.getIDToken" in auth:
        issues.append("trusted_source_authorize_must_not_mint_oidc")

    required_trusted = (
        "needs: trusted-source-authorize",
        "if: needs.trusted-source-authorize.outputs.authorized == 'true'",
        "permissions:",
        "contents: read",
        "id-token: write",
        "AUTHORIZED_URL: ${{ needs.trusted-source-authorize.outputs.deployment_url }}",
        "Mint short-lived GitHub OIDC identity",
        "uses: actions/github-script@v7",
        "const token = await core.getIDToken();",
        "core.setSecret(token);",
        "VERCEL_TRUSTED_OIDC_TOKEN: ${{ steps.oidc.outputs.token }}",
        'needs.trusted-source-authorize.outputs.source_git_sha',
        "python scripts/verify_vercel_trusted_source.py",
        "python scripts/verify_vercel_trusted_source_artifact.py",
        "archive: false",
    )
    for snippet in required_trusted:
        if snippet not in trusted:
            issues.append("trusted_source_job_missing:" + snippet)

    smoke_start = text.find("\n  smoke:")
    if smoke_start < 0:
        issues.append("smoke_job_missing")
    else:
        smoke = text[smoke_start:auth_start]
        if "id-token: write" in smoke:
            issues.append("public_smoke_must_not_have_oidc_authority")
        if "needs.trusted-source-authorize.outputs.source_git_sha" in smoke:
            issues.append("public_smoke_must_keep_event_sha_binding")

    if "VERCEL_TRUSTED_OIDC_TOKEN:" in text[:trusted_start]:
        issues.append("trusted_oidc_token_leaked_outside_trusted_job")

    if "echo ${{ steps.oidc.outputs.token }}" in text:
        issues.append("oidc_token_must_not_be_printed")

    if text.count("x-vercel-trusted-oidc-idp-token") != 0:
        issues.append("workflow_must_not_inline_trusted_oidc_header")

    return issues


def main() -> int:
    issues = validate()
    if issues:
        print("Vercel trusted-source workflow contract FAILED")
        for issue in issues:
            print(f"- {issue}")
        return 1

    print("Vercel trusted-source workflow contract OK")
    print("- public smoke: no OIDC authority")
    print("- authorization: production event + main ancestry, no OIDC")
    print("- trusted-source: only authorized ancestry may mint GitHub OIDC")
    print("- token handling: job-local, masked, environment-only, artifact-free")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
