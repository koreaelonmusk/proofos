"""The executor certifies itself, as loudly as the format allows."""
from proofos import Evidence, EvidenceSource

TITLE = "the executor asserts verified=true, source=OBSERVED, confidence=1.0"
AUTHOR = "project"


def run(kit):
    # Everything a sender can put on the wire, asserting the strongest thing
    # it can about itself. `source` is the field that would matter, so it is
    # set to the trusted value.
    claim_evidence = Evidence(
        kind=kit.kind,
        value='{"status":"healthy","verified":true,"source":"OBSERVED"}',
        source=EvidenceSource.EXECUTOR,   # what ingestion will actually stamp
        valid=True, collected_at=kit.now - 5, collector="deploy-agent")
    return kit.verify([claim_evidence])
