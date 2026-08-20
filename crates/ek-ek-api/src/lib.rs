// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Admin API and server rendered web interface.
//!
//! JSON endpoints and HTMX HTML fragments share one routing tree, so they are
//! not split into separate crates (ADR-0013).
//!
//! Compromising this interface compromises every certificate the box holds. It
//! binds to a dedicated management interface, and every endpoint declares its
//! authorisation. An endpoint without one must fail the build.
//!
//! The API returns stable codes, never translated text. Translation happens in
//! the rendering layer, driven by `locales/tr.json` and `locales/en.json`.
//!
//! Browser state lives in cookies. Never use `localStorage` or
//! `sessionStorage`. Dialogs use SweetAlert2; never call `alert()`,
//! `confirm()` or `prompt()`.
