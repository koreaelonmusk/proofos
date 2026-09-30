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

    marker = "\n  trusted-source:"
    start = text.find(marker)
    if start < 0:
        return ["trusted_source_job_missing"]
    trusted = text[start:]

    required = (
        "github.event.deployment.ref == 'main'",
        "github.event.deployment.environment == 'Production'",
        "github.event.deployment.environment == 'production'",
        "permissions:",
        "contents: read",
        "id-token: write",
        "Mint short-lived GitHub OIDC identity",
        "uses: actions/github-script@v7",
        "const token = await core.getIDToken();",
        "core.setSecret(token);",
        "VERCEL_TRUSTED_OIDC_TOKEN: ${{ steps.oidc.outputs.token }}",
        "python scripts/verify_vercel_trusted_source.py",
        "python scripts/verify_vercel_trusted_source_artifact.py",
        "archive: false",
    )
    for snippet in required:
        if snippet not in trusted:
            issues.append("trusted_source_job_missing:" + snippet)

    smoke_start = text.find("\n  smoke:")
    if smoke_start < 0:
        issues.append("smoke_job_missing")
    else:
        smoke = text[smoke_start:start]
        if "id-token: write" in smoke:
            issues.append("public_smoke_must_not_have_oidc_authority")

    if "VERCEL_TRUSTED_OIDC_TOKEN:" in text[:start]:
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
    print("- trusted-source: main + production only")
    print("- GitHub OIDC: job-local and masked")
    print("- token handling: environment-only, artifact-free")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
