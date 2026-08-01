"""THE PIN. The corpus this demo consumes, named by DIGEST, committed here as data.

⚠ THIS FILE IS THE TRUST ROOT. Everything the demo verifies traces back to ``CORPUS_SHA256`` below.
A wrong or truncated digest here is the one defect that makes every subsequent verification pass
against the wrong artifact — the checks would all run, all succeed, and all be about something else.
So the constant gets the same treatment as the code around it: there is a test that CORRUPTS one
character and requires the fetch to refuse. A pin that has never been seen to reject is a claim.

WHY A DIGEST AND NOT A TAG OR A COMMIT. A tag is mutable — it can be moved to point at other bytes.
A commit pins source, not the built artifact. Only the artifact digest pins the bytes this demo
actually consumes. The release name and URL below are CONVENIENCES for fetching; they are not
authority. If they disagree with the digest, the digest wins and the fetch refuses.

⚠ THIS IS THE FIRST THING IN ``gated`` THAT CONSUMES ``gated-uat`` CONTENT. Before this file, the
count of such references was zero. That makes the shape here a SPECIFICATION rather than an example:
whatever this permits, every later consumer will permit, because it will be read as the precedent.
Relaxing any of it is cheap now and expensive later.

UPDATING THE PIN (the ceremony, so the next person does not improvise one):
  1. the corpus repo cuts a successor release — the old tag is NEVER deleted;
  2. re-fetch, re-verify, and re-run the full demo green against the new artifact;
  3. update BOTH the digest and the expected counts below, in one commit, citing the new release;
  4. a reviewer compares digests. That review is the last human step protecting this file, which is
     why the corpus build recipe is deterministic — if digests churned without content changing, the
     reviewer would learn that churn is normal.
"""
from __future__ import annotations

# --- the artifact -------------------------------------------------------------------------------
CORPUS_RELEASE = "demo-corpus-v1"
CORPUS_ARTIFACT = "gated-demo-corpus.tar"
CORPUS_URL = (
    "https://github.com/fjwood69/gated-uat/releases/download/"
    f"{CORPUS_RELEASE}/{CORPUS_ARTIFACT}"
)

# THE TRUST ROOT. Verified against the published release on 2026-08-01 by downloading the artifact
# into a clean directory and checking it as a stranger would, not from the tree that built it.
CORPUS_SHA256 = "810e2f8f7c07269445fdfa89e2875ce907c091ffe54c8dbbd62c15936978088a"

# --- what the artifact must contain ---------------------------------------------------------------
# EXACT SET. Not a minimum. A corpus with every member's bytes correct is still wrong if it carries
# one member too few or one too many, and a content check cannot see that.
EXPECTED_MEMBERS = frozenset({
    "fixtures/retry-swallow-v2/main.py",
    "fixtures/retry-swallow-v2-mutated-behavioural/main.py",
    "fixtures/retry-swallow-v2-mutated-cosmetic/main.py",
    "fixtures/two-unconditional-egresses-v1/main.py",
    "fixtures/retry-good-v2/main.py",
    "MEASURED.json",
    "README.md",
    "WARRANT.md",
    "expectations.py",
    "SHA256SUMS",
})

# --- the expectations, held HERE rather than read from the fetched artifact ------------------------
# ⚠ THE ANTI-CIRCULARITY RULE, and it is the reason these literals exist at all. If the demo took its
# expectations SOLELY from the corpus it just downloaded, it would be checking the artifact against
# the artifact — self-referential, always green, and a pattern every later consumer would copy.
#
# So the authority is here, in the consumer, and the corpus's own ``MEASURED.json`` is cross-checked
# against it. A disagreement is TERMINAL, and the moment it fires is exactly the moment it should:
# when someone updates the pin without re-reading what changed.
EXPECTED_EGRESS: dict[str, int] = {
    "retry-swallow-v2": 1,
    "retry-swallow-v2-mutated-behavioural": 3,
    "retry-swallow-v2-mutated-cosmetic": 1,
    "two-unconditional-egresses-v1": 2,
    "retry-good-v2": 3,
}

# DEMO POLICY, and only that. Deliberately NOT in the corpus: freezing a threshold into a public
# digest-pinned artifact would make one demo's policy into corpus truth that every later consumer
# conforms to. The corpus records COUNTS; the verdict rule lives with the consumer that applies it.
ADMIT_AT_OR_ABOVE = 2


# --- THE ZERO CONTROL, pinned CONSUMER-SIDE as an interim -------------------------------------
# ⚠ THE FLOOR IS UNDEMONSTRATED WITHOUT THIS. Every frozen corpus count is NONZERO (1, 3, 1, 2, 3),
# which is equally consistent with an instrument reporting ``M_true - k``, or with one counting a
# quantity merely CORRELATED with egress. Row 4 calibrates "2 means 2" at a single point; nothing
# shows the counter can read ZERO. That is a hole in the central claim rather than a footnote.
#
# It is pinned HERE and not in the corpus because the corpus is already tagged: adding a member would
# force a new outer digest and a pin move, and the floor should not wait for that.
#
# ⚠ A CONTROL THAT DISAGREES IS NOT DRIFT — IT IS AN INVALID INSTRUMENT. A zero-egress artifact
# measuring nonzero says nothing about any artifact; it says the counter is wrong, which makes every
# other row's number suspect. Shown as a sixth drift row it would produce a table where one row
# quietly means "do not believe the other five", with nothing telling a reader which.
#
# ⚠ PROMOTION PATH, written down NOW rather than under time pressure at the next cut. It has THREE
# moving parts and they go together:
#     1. the control becomes a corpus member at the next tag, with its own by-construction derivation
#        and a row in the warrant;
#     2. the outer digest changes, so CORPUS_SHA256 above is re-pinned in the same commit;
#     3. THIS BLOCK IS DELETED. It must not survive as a second source of truth for a member the
#        corpus now carries — that is precisely the drift-between-two-records defect this project
#        keeps finding.
CONTROL_NAME = "zero-egress-control"
CONTROL_SOURCE = '''"""zero-egress-control — makes NO boundary attempt at all.

The floor. If the counter reports anything other than 0 for this, it is not measuring what it claims
to measure, and no other row's number can be trusted.
"""
if __name__ == "__main__":
    pass
'''
CONTROL_EXPECTED_EGRESS = 0
