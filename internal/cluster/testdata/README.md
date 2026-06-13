Copy of aikey-hub/contract/daemon-status.fixture.json (canonical).
Kept as a copy because aikey-proxy and aikey-hub are separate repos and a
cross-repo relative path would break standalone checkouts. If the daemon
status contract changes, update BOTH files (the Rust test in aikey-hub pins
the canonical one; TestNodeHealthSource_ForwardsDaemonFixture pins this copy).
