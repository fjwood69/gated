"""Isolation backends — implementations of ``core.Sandbox`` (open Apache core).

subprocess.py = WEAK (1.2), oci.py = HERMETIC (1.3), microvm.py = HARDENED
(deferred). Swappable; the engine selects one by the policy's required
IsolationLevel. No proprietary dependencies belong here.
"""
