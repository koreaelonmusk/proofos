"""Skip the wire: construct Evidence already marked OBSERVED."""
from proofos import Evidence, EvidenceSource

TITLE = "hand the verifier an Evidence object whose source is OBSERVED"
AUTHOR = "project"


def run(kit):
    # If provenance were data rather than authority, this would be the whole
    # attack: declare the value you want and pass it in.
    forged = Evidence(
        kind=kit.kind, value="GET /health -> 200",
        source=EvidenceSource.OBSERVED,
        valid=True, collected_at=kit.now - 5, collector="proofos-collector")
    return kit.verify([forged])
