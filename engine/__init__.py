"""Orchestration — runs checks using ``core`` contracts + a ``sandbox`` backend
(open Apache core).

Selects a backend, runs trials, applies multi-trial/unanimity, and emits a
Verdict. Enforces gate policy (e.g. a WEAK pass does not satisfy a HERMETIC
required check). No proprietary dependencies belong here.
"""
