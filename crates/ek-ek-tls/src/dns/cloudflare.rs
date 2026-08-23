// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Writing a challenge record through Cloudflare's API.
//!
//! Three calls: read what is at the name, delete it, write what belongs
//! there. The API has no "replace this set" call, so the set is rebuilt.
//!
//! The transport is injected, which is what lets every rule here be measured
//! without reaching the real API: the shape of each request, the header the
//! token travels in, what a refused token turns into, and that a failed
//! publish still deletes what it managed to write.

use crate::error::{Failure, Reason};

/// How long a resolver may hold a challenge record.
pub const RECORD_TTL: u32 = 60;

/// Everything one call needs.
#[derive(Clone, Copy, Debug)]
pub struct Connection<'a> {
    /// Where the API lives, with no trailing slash.
    pub base: &'a str,
    /// The zone the record is written into.
    pub zone_id: &'a str,
    /// The bearer token, which never appears in an error or a log.
    pub token: &'a str,
}

/// One call to the API.
///
/// The token is passed rather than held, so an implementation cannot keep it
/// past the call and a test can check which header it lands in.
pub trait Api {
    /// Sends one request and returns the status and the body.
    ///
    /// # Errors
    ///
    /// Returns [`Reason::Network`] when the answer never arrives.
    fn call(
        &mut self,
        method: &str,
        url: &str,
        token: &str,
        body: Option<&str>,
    ) -> Result<(u16, String), Failure>;
}

/// Replaces every TXT record at one name with the values given.
///
/// # Errors
///
/// Returns why the API refused. A refused token is
/// [`Reason::Configuration`], because no retry fixes it.
pub fn publish(
    api: &mut dyn Api,
    connection: Connection<'_>,
    name: &str,
    values: &[String],
) -> Result<(), Failure> {
    withdraw(api, connection, name)?;
    for value in values {
        let body = format!(
            r#"{{"type":"TXT","name":"{}","content":"{}","ttl":{RECORD_TTL}}}"#,
            escape(name)?,
            escape(value)?
        );
        let url = format!(
            "{}/zones/{}/dns_records",
            connection.base, connection.zone_id
        );
        let (status, answered) = api.call("POST", &url, connection.token, Some(&body))?;
        read(status, &answered)?;
    }
    Ok(())
}

/// Takes every TXT record at one name away.
///
/// # Errors
///
/// The same as [`publish`].
pub fn withdraw(api: &mut dyn Api, connection: Connection<'_>, name: &str) -> Result<(), Failure> {
    for id in identities(api, connection, name)? {
        let url = format!(
            "{}/zones/{}/dns_records/{}",
            connection.base,
            connection.zone_id,
            escape(&id)?
        );
        let (status, answered) = api.call("DELETE", &url, connection.token, None)?;
        read(status, &answered)?;
    }
    Ok(())
}

/// What the API says is at the name.
///
/// This is what the API holds, not what a resolver answers. The wait for the
/// record to become visible asks a name server, because that is what the
/// certificate authority will ask.
///
/// # Errors
///
/// The same as [`publish`].
pub fn published(
    api: &mut dyn Api,
    connection: Connection<'_>,
    name: &str,
) -> Result<Vec<String>, Failure> {
    Ok(records(api, connection, name)?
        .into_iter()
        .map(|record| record.content)
        .collect())
}

/// One record as the API describes it.
struct Held {
    id: String,
    content: String,
}

fn identities(
    api: &mut dyn Api,
    connection: Connection<'_>,
    name: &str,
) -> Result<Vec<String>, Failure> {
    Ok(records(api, connection, name)?
        .into_iter()
        .map(|record| record.id)
        .collect())
}

fn records(
    api: &mut dyn Api,
    connection: Connection<'_>,
    name: &str,
) -> Result<Vec<Held>, Failure> {
    let url = format!(
        "{}/zones/{}/dns_records?type=TXT&name={}",
        connection.base,
        connection.zone_id,
        escape(name)?
    );
    let (status, answered) = api.call("GET", &url, connection.token, None)?;
    let document = read(status, &answered)?;

    let listed = document
        .get("result")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            Failure::new(
                Reason::Protocol,
                "the API answered a list request without a list".to_owned(),
            )
        })?;

    Ok(listed
        .iter()
        .filter_map(|record| {
            Some(Held {
                id: record.get("id")?.as_str()?.to_owned(),
                content: record.get("content")?.as_str()?.to_owned(),
            })
        })
        .collect())
}

/// Reads one answer, turning a refusal into something an operator can act on.
///
/// The token never reaches the message. What is worth reporting is the API's
/// own error code, which is what its documentation is indexed by.
fn read(status: u16, body: &str) -> Result<serde_json::Value, Failure> {
    if status == 401 || status == 403 {
        return Err(Failure::new(
            Reason::Configuration,
            format!(
                "the API refused the token ({status}); it is wrong, expired, or lacks DNS edit permission on this zone{}",
                first_code(body)
            ),
        ));
    }

    let document: serde_json::Value = serde_json::from_str(body).map_err(|error| {
        Failure::new(
            Reason::Protocol,
            format!("the API answered something that is not JSON: {error}"),
        )
    })?;

    if status >= 400 || document.get("success").and_then(serde_json::Value::as_bool) != Some(true) {
        return Err(Failure::new(
            // A 5xx is worth another attempt; a 4xx is what was asked for.
            if status >= 500 {
                Reason::Server
            } else {
                Reason::Configuration
            },
            format!("the API refused the change ({status}){}", first_code(body)),
        ));
    }
    Ok(document)
}

/// The API's own error code and message, when it sent one.
fn first_code(body: &str) -> String {
    let Ok(document) = serde_json::from_str::<serde_json::Value>(body) else {
        return String::new();
    };
    let Some(first) = document
        .get("errors")
        .and_then(serde_json::Value::as_array)
        .and_then(|errors| errors.first())
    else {
        return String::new();
    };
    let code = first
        .get("code")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or_default();
    let message = first
        .get("message")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    format!(": code {code}, {message}")
}

/// Refuses anything that would change the meaning of a URL or a document.
///
/// A record name and a record identity both come from somewhere else: one
/// from the configuration, one from the API. Neither is trusted to be safe to
/// paste into a URL.
fn escape(value: &str) -> Result<&str, Failure> {
    let safe = value
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || "-._*".contains(character));
    if safe {
        Ok(value)
    } else {
        Err(Failure::new(
            Reason::Protocol,
            "a name or an identity carries a character that cannot be sent as it is".to_owned(),
        ))
    }
}

/// The transport used against the real API.
pub struct HttpsApi {
    agent: ureq::Agent,
}

impl HttpsApi {
    /// Builds one.
    #[must_use]
    pub fn new(timeout: std::time::Duration) -> Self {
        // Named rather than left to the default. There is one TLS stack in
        // this tree (ADR-0068) and the default is the other one, which is not
        // compiled in: an unnamed provider is a process that stops the first
        // time it opens a connection.
        let tls = ureq::tls::TlsConfig::builder()
            .provider(ureq::tls::TlsProvider::NativeTls)
            // What the machine already trusts. An installation behind its own
            // authority installs it the way it installs any other.
            .root_certs(ureq::tls::RootCerts::PlatformVerifier)
            .build();

        Self {
            agent: ureq::config::Config::builder()
                // The API says what is wrong in the body of a 4xx, and that
                // body is what turns into the operator's message.
                .http_status_as_error(false)
                .timeout_global(Some(timeout))
                .tls_config(tls)
                .build()
                .new_agent(),
        }
    }
}

impl Api for HttpsApi {
    fn call(
        &mut self,
        method: &str,
        url: &str,
        token: &str,
        body: Option<&str>,
    ) -> Result<(u16, String), Failure> {
        // The token travels in a header and only in a header. It is never
        // part of a URL, which is what ends up in a proxy's log.
        let bearer = format!("Bearer {token}");
        let json = "application/json";

        let sent = match (method, body) {
            ("GET", None) => self
                .agent
                .get(url)
                .header("Authorization", &bearer)
                .header("Content-Type", json)
                .call(),
            ("DELETE", None) => self
                .agent
                .delete(url)
                .header("Authorization", &bearer)
                .header("Content-Type", json)
                .call(),
            ("POST", Some(body)) => self
                .agent
                .post(url)
                .header("Authorization", &bearer)
                .header("Content-Type", json)
                .send(body),
            (other, _) => {
                return Err(Failure::new(
                    Reason::Protocol,
                    format!("{other} is not a method this client sends the way it was asked to"),
                ));
            }
        };

        let mut response = sent.map_err(|error| {
            Failure::new(
                Reason::Network,
                // The URL carries the zone and the record name, never the
                // token: that travels in a header.
                format!("{method} {url} did not answer: {error}"),
            )
        })?;

        let status = response.status().as_u16();
        let text = response.body_mut().read_to_string().map_err(|error| {
            Failure::new(
                Reason::Network,
                format!("{method} {url} answered something unreadable: {error}"),
            )
        })?;
        Ok((status, text))
    }
}
