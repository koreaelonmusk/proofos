"""GitHub as a transport: normalize what it says, render what ProofOS decided.

A pull request is a place where a great many things assert that work is done.
The body says so. The commit message says so. A bot leaves a comment saying all
checks passed. Every one of those is written by, or on behalf of, the party
whose work is under review, and none of them is evidence.

This module therefore does two things and no others:

* it turns a pull request into a claim and some non-authoritative metadata,
  using the same neutral model any other transport uses, and
* it renders a ``VerificationResult`` the kernel already produced into a check
  a person can read.

There is no verification here. ``verify_completion`` is not imported, and a test
parses this file to keep it that way. GitHub changes how a claim arrives; it does
not change what would settle it.

## The conclusion mapping, and why ``neutral`` is absent

GitHub treats a ``neutral`` conclusion as passing for the purpose of required
status checks. A protected branch with ProofOS as a required check would
therefore merge on an abstention -- the system would have said "I do not have
enough evidence" and the branch would have taken that as a yes. That is
fail-open, in the product whose entire argument is failing closed.

So the vocabulary contains no ``neutral``. Not a value that is rejected: a value
that does not exist, in the same way the plugin manifest has no word for
"verify". ABSTAIN maps to ``action_required``, which is both safe and accurate --
an abstention is not a failed test, it is a statement that something is still
needed.

``failure`` is deliberately not used for verdicts either. It belongs to a
transport or runtime that could not do its job, and conflating "ProofOS declined
to certify" with "the pipeline broke" would lose the distinction that makes the
first one useful.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Iterable, Mapping

from .adapters import (
    ActorRef,
    AdapterEnvelope,
    AdapterError,
    AgentEvent,
    Claim,
    TaskRef,
    ToolResult,
)
from .verifier import VerificationResult, VerificationStatus

#: Where in a pull request a statement came from. Every one of these is a claim;
#: the enum exists so a summary can tell a reviewer *what* was ignored, which is
#: more useful than silently dropping it.
class ClaimSource(StrEnum):
    PR_BODY = "pull request body"
    PR_TITLE = "pull request title"
    COMMIT_MESSAGE = "commit message"
    COMMENT = "comment"
    CHECK_ANNOTATION = "check annotation"
    REVIEW = "review"


class CheckConclusion(StrEnum):
    """What ProofOS may put on a check.

    Two values. ``neutral`` is absent because GitHub counts it as passing for a
    required check, so an abstention would satisfy branch protection. ``failure``
    is absent because it belongs to a transport that broke rather than to a
    verdict that declined.
    """

    SUCCESS = "success"
    ACTION_REQUIRED = "action_required"


@dataclass(frozen=True)
class CheckRun:
    """A rendered check. Data for a transport to send; it sends nothing itself."""

    name: str
    conclusion: CheckConclusion
    title: str
    summary: str
    #: What was read and deliberately not counted, so the reviewer can see it.
    ignored_claims: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "conclusion": str(self.conclusion),
            "output": {"title": self.title, "summary": self.summary},
        }


def conclusion_for(result: VerificationResult) -> CheckConclusion:
    """Map a verdict onto a check conclusion.

    One branch, and it reads the kernel's own status rather than anything about
    the pull request. A check whose conclusion could be influenced by the PR it
    is checking would be reporting the PR's opinion of itself.
    """
    if result.status is VerificationStatus.VERIFIED:
        return CheckConclusion.SUCCESS
    return CheckConclusion.ACTION_REQUIRED


def _claim_text(payload: Mapping[str, Any]) -> tuple[str, tuple[str, ...]]:
    """Assemble the claim, and record which parts of the PR it came from."""
    pieces: list[str] = []
    ignored: list[str] = []
    for key, label in (("title", ClaimSource.PR_TITLE),
                       ("body", ClaimSource.PR_BODY)):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            pieces.append(value.strip())
            ignored.append(str(label))
    for key, label in (("commits", ClaimSource.COMMIT_MESSAGE),
                       ("comments", ClaimSource.COMMENT),
                       ("reviews", ClaimSource.REVIEW)):
        entries = payload.get(key) or ()
        if not isinstance(entries, (list, tuple)):
            raise AdapterError(f"'{key}' must be a list", source="github payload",
                               path=key)
        if entries:
            ignored.append(str(label))
    return (" | ".join(pieces) or "(no claim text)", tuple(dict.fromkeys(ignored)))


def normalize_pull_request(payload: Mapping[str, Any], *,
                           adapter_id: str = "proofos-github") -> AdapterEnvelope:
    """Turn a pull request into a claim and some metadata.

    Check runs become tool results. A green CI run is real and useful and still
    not independent of the change that produced it -- whether it satisfies
    anything is a question for a requirement, answered by the kernel, not by the
    fact that GitHub coloured it green.
    """
    if not isinstance(payload, Mapping):
        raise AdapterError("payload must be an object", source="github payload")

    repository = str(payload.get("repository") or "").strip()
    number = payload.get("number")
    if not repository or not isinstance(number, int):
        raise AdapterError("a pull request needs 'repository' and an integer "
                           "'number'", source="github payload")
    head_sha = str(payload.get("head_sha") or "").strip()
    if not head_sha:
        raise AdapterError("missing 'head_sha'", source="github payload",
                           fix="a claim about a pull request is a claim about a "
                               "commit; without one there is nothing to verify "
                               "against")

    author = payload.get("author")
    if not isinstance(author, str) or not author.strip():
        raise AdapterError("missing 'author'", source="github payload")

    text, ignored = _claim_text(payload)

    events: list[AgentEvent] = []
    for entry in payload.get("comments") or ():
        if not isinstance(entry, Mapping):
            raise AdapterError("each comment must be an object",
                               source="github payload", path="comments")
        events.append(AgentEvent(
            name="comment",
            detail=f"{entry.get('author', 'unknown')}: "
                   f"{str(entry.get('body', ''))[:512]}",
            at=entry.get("at"),
        ))

    tools: list[ToolResult] = []
    for entry in payload.get("check_runs") or ():
        if not isinstance(entry, Mapping):
            raise AdapterError("each check run must be an object",
                               source="github payload", path="check_runs")
        tools.append(ToolResult(
            tool=str(entry.get("name", "check")),
            payload={"conclusion": entry.get("conclusion"),
                     "status": entry.get("status")},
            at=entry.get("at"),
        ))

    return AdapterEnvelope(
        claim=Claim(
            text=text,
            actor=ActorRef(actor_id=author.strip(), framework="github"),
            task=TaskRef(task_id=f"{repository}#{number}",
                         execution_id=head_sha),
            at=payload.get("at"),
        ),
        events=tuple(events),
        tool_results=tuple(tools),
        adapter_id=adapter_id,
        transport="github",
        metadata={"ignored_claims": list(ignored),
                  "repository": repository,
                  "head_sha": head_sha},
    )


def render_check(result: VerificationResult, *,
                 name: str = "ProofOS",
                 ignored_claims: Iterable[str] = (),
                 requirement_count: int | None = None) -> CheckRun:
    """Render a decision a person has to act on.

    Not a JSON dump. Somebody looking at a red check wants four things: what the
    verdict was, why, what is still missing, and what to do -- and, here, which
    of the confident-sounding text on the page was read and not counted.
    """
    conclusion = conclusion_for(result)
    verified = result.status is VerificationStatus.VERIFIED
    accepted = [a for a in result.assessments if a.satisfies_requirement]
    satisfied = len({a.kind for a in accepted})
    total = requirement_count if requirement_count is not None else \
        satisfied + len(result.missing)

    title = "ProofOS: verified" if verified else "ProofOS: action required"
    lines = [
        f"## ProofOS: {'VERIFIED' if verified else 'ACTION REQUIRED'}",
        "",
        "**Verdict**", str(result.status), "",
        "**Reason**", str(result.failure), "",
        "**Satisfied**", f"{satisfied} / {total} requirements", "",
    ]

    if result.missing:
        lines += ["**Missing**"]
        lines += [f"- {kind}" for kind in result.missing]
        lines.append("")

    refused = [a for a in result.assessments if not a.accepted_by_verifier]
    if refused:
        lines += ["**Evidence refused**"]
        for a in refused:
            reason = a.rejection_reason or "not accepted"
            lines.append(f"- `{a.kind}` from `{a.collector}` ({a.source}) — {reason}")
        lines.append("")

    claims = tuple(ignored_claims)
    if claims:
        lines += ["**Ignored as claims**"]
        lines += [f"- {item}" for item in claims]
        lines += ["",
                  "_These were written by or on behalf of the change under "
                  "review. A statement that the work is done is the thing being "
                  "checked, not evidence for it._", ""]

    lines += ["**Next action**", _next_action(result)]

    return CheckRun(name=name, conclusion=conclusion, title=title,
                    summary="\n".join(lines).rstrip() + "\n",
                    ignored_claims=claims)


def _next_action(result: VerificationResult) -> str:
    if result.status is VerificationStatus.VERIFIED:
        return "None. Every requirement is satisfied by independent evidence."
    reason = str(result.failure)
    return {
        "EVIDENCE_UNTRUSTED": "Provide independent evidence. A report from the "
                              "change under review cannot satisfy a requirement.",
        "EVIDENCE_MISSING": "Provide evidence of the missing kinds.",
        "EVIDENCE_STALE": "Observe again. The evidence is real but outside its "
                          "freshness horizon.",
        "EVIDENCE_INVALID": "The governing observation reports failure. Fix the "
                            "system, not the evidence.",
        "EVIDENCE_TAMPERED": "A record no longer matches its own digest. Do not "
                             "trust this evidence set.",
    }.get(reason, "Provide evidence that satisfies every requirement.")


#: Tier 2. Imported from ``proofos.github`` by whoever is wiring a check; the
#: root API is for someone verifying a claim.
__all__ = [
    "ClaimSource",
    "CheckConclusion",
    "CheckRun",
    "conclusion_for",
    "normalize_pull_request",
    "render_check",
]
