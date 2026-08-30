"""A perfectly valid signature from an identity nobody registered."""
from proofos import Evidence, EvidenceSource

TITLE = "evidence attributed to a collector id the registry does not know"
AUTHOR = "project"


def run(kit):
    # The attacker can sign anything it likes; what it cannot do is be someone
    # the verifier trusts. Naming a plausible collector is the cheap version of
    # the same attack, and it should fail identically.
    impersonated = Evidence(
        kind=kit.kind, value="GET /health -> 200 in 41ms",
        source=EvidenceSource.EXECUTOR,
        valid=True, collected_at=kit.now - 5,
        collector=kit.attacker_identity)
    return kit.verify([impersonated])
