"""Boundary observation — host-side flow counting (open Apache core).

Reads egress at the sandbox boundary from OUTSIDE the container
(--network=none + conntrack/eBPF/veth tap), post-run, as final-state counters —
never in-process state the artifact could forge (NFR4). Lands at 1.4.
"""
