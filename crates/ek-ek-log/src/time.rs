// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The timestamp every record opens with.

use chrono::SecondsFormat;

/// Now, as RFC 3339 in UTC with milliseconds.
///
/// UTC rather than local time, because a cluster spans nodes and two records
/// have to be comparable without knowing which node wrote them. Milliseconds
/// rather than seconds, because two requests inside one second is ordinary.
#[must_use]
pub fn now() -> String {
    chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}
