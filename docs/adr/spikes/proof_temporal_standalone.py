"""Proof / Analysis: Temporal Standalone Mode and Storage Coupling.

Criterion: Standalone vs Platform mode with zero external orchestration daemons
and direct reuse of AgentOS 1.2 MongoDB and SQLite storage ports.

Finding:
1. Temporal requires a running Temporal Server (gRPC service, history service, matching service)
   backed by an external database (PostgreSQL, MySQL, or Cassandra).
2. The Python Temporal SDK connects to this server via Client.connect("localhost:7233").
3. Standalone mode cannot function out-of-the-box in lightweight local environments (e.g. single python process,
   packaged desktop agent) without spawning an external binary or Docker container.
4. Temporal owns workflow state persistence and event history in its own internal schema,
   preventing direct reuse of AgentOS 1.2 RunRepository, EventStore, and CheckpointStore ports.
5. Workflows are imperative Python code, preventing compile-time / publish-time static graph analysis
   to prove information flow control from untrusted sources to sinks.
"""

def evaluate_temporal_coupling():
    requirements = {
        "standalone_in_process": False,  # Requires external Temporal cluster/daemon
        "reuses_agentos_1_2_storage": False,  # Temporal maintains its own database schema
        "declarative_static_publish_gate": False,  # Imperative workflow code cannot be statically checked
        "durable_waiting_states": True,  # Native signal/timer support
        "event_sourced_replay": True,  # Excellent native replay
    }
    return requirements

if __name__ == "__main__":
    results = evaluate_temporal_coupling()
    for k, v in results.items():
        print(f"{k}: {v}")
    print("Temporal evaluation: Disqualified for Standalone mode and static graph verification.")
