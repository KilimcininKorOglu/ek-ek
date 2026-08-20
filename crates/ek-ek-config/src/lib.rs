// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Configuration domain model, serialisation and validation.
//!
//! This is the base layer. It depends on no other workspace crate, so every
//! other layer can use its types without creating a dependency cycle.
//!
//! Error values carry a stable code and structured parameters, never a
//! user-facing string, because the UI layer performs the translation.
