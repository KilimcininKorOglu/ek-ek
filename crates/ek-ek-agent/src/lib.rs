// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The `node-agent` process: supervises `data-plane`, drives the upgrade
//! choreography, carries health state and coordinates the cluster.
//!
//! This process also hosts the VRRP state machine and the web interface, so it
//! is the one that must stay alive across a `data-plane` replacement.
//!
//! When `data-plane` dies, release the VIP immediately (ADR-0033). A node that
//! holds a VIP but serves no traffic is worse than a failover.
//!
//! Drop VRRP priority only on node-local faults. Never drop it on a shared
//! backend failure, because every node would drop together and the VIP would
//! travel for nothing.
