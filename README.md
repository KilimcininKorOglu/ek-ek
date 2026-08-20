# ek-ek

**English** | [Türkçe](README.tr.md)

`ek-ek` is a load balancer that combines traffic distribution and high availability in a single Rust binary. Today this job takes two separate programs, HAProxy and Keepalived. They are configured through separate text files, they know nothing about each other's state, and configuring them correctly requires protocol level knowledge. `ek-ek` does the same job with one configuration model, one web interface, and one service per node.

## Who it is for

One or two person IT teams in mid-size organizations. The goal is to let someone build a working, redundant load balancer without knowing what a VRRP priority value is or how HAProxy backend syntax works.

## Status

Under development. No usable release has been published yet.

## Architecture

Every node runs the same binary. There is no central management server; nodes connect to each other as peers.

The binary runs two processes:

| Process            | Responsibility                                                                                      |
|--------------------|-----------------------------------------------------------------------------------------------------|
| `ek-ek node-agent` | Configuration store, cluster membership, VRRP state machine, VIP management, web interface and API. |
| `ek-ek data-plane` | The traffic itself. HTTP, TCP and UDP proxying, TLS termination, health checks.                     |

The two processes are separate because adding a new listening port replaces the `data-plane` process. If VRRP ran inside that same process, the replacement would briefly advertise the VIP from two nodes at once.

Configuration is replicated with Raft. Losing Raft quorum does not affect traffic: configuration cannot be changed in that state, but the existing configuration keeps serving. VIP ownership is never derived from Raft leadership.

### Components used

- [pingora](https://github.com/cloudflare/pingora), HTTP data plane.
- [rustls](https://github.com/rustls/rustls), TLS.
- [openraft](https://github.com/databendlabs/openraft), configuration replication.
- SQLite, state machine store.

## Supported platforms

Linux only. Target distributions are Debian, Ubuntu and the RHEL family.

## License

Dual licensed:

- [AGPL-3.0](LICENSE). Default license, free of charge.
- [Commercial license](LICENSE-COMMERCIAL.md). For closed source use.

## Contributing

External contributions are not accepted until a CLA process is in place. The dual license model requires copyright to be held by a single party, and merging an unsigned contribution would break that model irreversibly.
