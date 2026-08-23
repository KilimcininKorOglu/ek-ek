// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! A stand-in for Cloudflare's DNS API.
//!
//! The measurement must never reach the real API: a test that writes into
//! somebody's zone is a test nobody can run twice, and the token it would need
//! is a credential this repository cannot hold. So the endpoint is stood in
//! for and the client is the real one.
//!
//! What it does with a change is real, though. Every accepted call is applied
//! to the lab's name server with `nsupdate`, BIND's own client, so the
//! certificate authority looks the record up and finds it. Only the shape of
//! the API is imitated; the DNS write is not.
//!
//! It writes the certificate it serves to a file, because nothing trusts a
//! certificate it made up for itself. Whoever runs this puts that file in the
//! trust store of the machine that will call it.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::ssl::{SslAcceptor, SslMethod};
use openssl::x509::extension::{BasicConstraints, SubjectAlternativeName};
use openssl::x509::{X509, X509NameBuilder};

/// How long a record is held, matching what the product asks for.
const TTL: u32 = 60;

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(said) => {
            eprintln!("standin-cloudflare: {said}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// Everything this was told.
struct Told {
    listen: String,
    zone_id: String,
    token: String,
    dns_server: String,
    dns_zone: String,
    /// A key file for `nsupdate`, written at start.
    ///
    /// A file rather than an argument: an argument is visible in the process
    /// table to every user on the machine.
    key_file: String,
    cert_out: String,
    names: Vec<String>,
    addresses: Vec<String>,
    /// Accept every change and apply none of it to the name server.
    ///
    /// A provider whose API took the change and whose zone has not caught up
    /// yet. That is the case the propagation timeout exists for, and it is
    /// also the one that has to leave nothing behind.
    no_dns: bool,
}

fn run() -> Result<(), String> {
    let told = read_arguments()?;
    let (certificate, key) = self_signed(&told.names, &told.addresses)?;

    let pem = certificate
        .to_pem()
        .map_err(|error| format!("the certificate could not be written out: {error}"))?;
    std::fs::write(&told.cert_out, &pem)
        .map_err(|error| format!("{} could not be written: {error}", told.cert_out))?;

    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls())
        .map_err(|error| format!("a TLS listener could not be prepared: {error}"))?;
    builder
        .set_private_key(&key)
        .and_then(|()| builder.set_certificate(&certificate))
        .map_err(|error| format!("the certificate could not be installed: {error}"))?;
    let acceptor = builder.build();

    let listener = TcpListener::bind(&told.listen)
        .map_err(|error| format!("{} could not be bound: {error}", told.listen))?;
    println!("listening on {}", told.listen);
    flush();

    let mut records: BTreeMap<String, (String, String)> = BTreeMap::new();
    static NEXT: AtomicU64 = AtomicU64::new(1);

    for stream in listener.incoming() {
        let stream = match stream {
            Ok(stream) => stream,
            Err(error) => {
                eprintln!("standin-cloudflare: a connection failed: {error}");
                continue;
            }
        };
        let mut tls = match acceptor.accept(stream) {
            Ok(tls) => tls,
            Err(error) => {
                eprintln!("standin-cloudflare: a handshake failed: {error}");
                continue;
            }
        };

        match answer(&mut tls, &told, &mut records, &NEXT) {
            Ok(said) => println!("{said}"),
            Err(said) => eprintln!("standin-cloudflare: {said}"),
        }
        flush();
        let _ = tls.shutdown();
    }
    Ok(())
}

/// Reads one request and writes one answer.
fn answer(
    stream: &mut openssl::ssl::SslStream<std::net::TcpStream>,
    told: &Told,
    records: &mut BTreeMap<String, (String, String)>,
    next: &AtomicU64,
) -> Result<String, String> {
    let (method, target, headers, body) = request(stream)?;

    let authorised = headers
        .get("authorization")
        .is_some_and(|value| value == &format!("Bearer {}", told.token));
    if !authorised {
        write_json(
            stream,
            403,
            r#"{"success":false,"errors":[{"code":9109,"message":"Invalid access token"}],"result":null}"#,
        )?;
        return Ok(format!("refused {method} {target}: wrong token"));
    }

    let prefix = format!("/client/v4/zones/{}/dns_records", told.zone_id);
    if !target.starts_with(&prefix) {
        write_json(
            stream,
            404,
            r#"{"success":false,"errors":[{"code":7003,"message":"Could not route to this path"}],"result":null}"#,
        )?;
        return Ok(format!("refused {method} {target}: unknown path"));
    }
    let rest = &target[prefix.len()..];

    match method.as_str() {
        "GET" => {
            let wanted = query(rest, "name");
            let listed: Vec<String> = records
                .iter()
                .filter(|(_, (name, _))| wanted.as_deref().is_none_or(|wanted| name == wanted))
                .map(|(id, (name, content))| {
                    format!(r#"{{"id":"{id}","type":"TXT","name":"{name}","content":"{content}"}}"#)
                })
                .collect();
            write_json(
                stream,
                200,
                &format!(
                    r#"{{"success":true,"errors":[],"result":[{}]}}"#,
                    listed.join(",")
                ),
            )?;
            Ok(format!("listed {} record(s)", listed.len()))
        }
        "POST" => {
            let name = field(&body, "name").ok_or("the request named no record")?;
            let content = field(&body, "content").ok_or("the request carried no value")?;
            update(told, &format!("update add {name}. {TTL} TXT \"{content}\""))?;
            let id = format!("record{}", next.fetch_add(1, Ordering::Relaxed));
            records.insert(id.clone(), (name.clone(), content.clone()));
            write_json(
                stream,
                200,
                &format!(r#"{{"success":true,"errors":[],"result":{{"id":"{id}"}}}}"#),
            )?;
            Ok(format!("wrote {name}"))
        }
        "DELETE" => {
            let id = rest.trim_start_matches('/').to_owned();
            let Some((name, content)) = records.remove(&id) else {
                write_json(
                    stream,
                    404,
                    r#"{"success":false,"errors":[{"code":81044,"message":"Record does not exist"}],"result":null}"#,
                )?;
                return Ok(format!("refused DELETE {id}: no such record"));
            };
            update(
                told,
                &format!("update delete {name}. {TTL} TXT \"{content}\""),
            )?;
            write_json(
                stream,
                200,
                &format!(r#"{{"success":true,"errors":[],"result":{{"id":"{id}"}}}}"#),
            )?;
            Ok(format!("deleted {name}"))
        }
        other => {
            write_json(
                stream,
                405,
                r#"{"success":false,"errors":[{"code":7003,"message":"Method not allowed"}],"result":null}"#,
            )?;
            Ok(format!("refused {other} {target}"))
        }
    }
}

/// Applies one change to the lab's name server.
///
/// Through `nsupdate`, which is BIND's own client. Writing the update here
/// would measure this product's encoder twice and the name server not at all.
fn update(told: &Told, change: &str) -> Result<(), String> {
    if told.no_dns {
        return Ok(());
    }
    let script = format!(
        "server {}\nzone {}\n{change}\nsend\n",
        told.dns_server, told.dns_zone
    );

    let mut child = Command::new("nsupdate")
        .args(["-k", &told.key_file])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|error| format!("nsupdate could not be started: {error}"))?;
    child
        .stdin
        .take()
        .ok_or("nsupdate took no input")?
        .write_all(script.as_bytes())
        .map_err(|error| format!("nsupdate could not be told what to do: {error}"))?;
    let finished = child
        .wait_with_output()
        .map_err(|error| format!("nsupdate did not finish: {error}"))?;
    if !finished.status.success() {
        return Err(format!(
            "nsupdate refused the change: {}",
            String::from_utf8_lossy(&finished.stderr)
        ));
    }
    Ok(())
}

/// Reads one HTTP request.
fn request(
    stream: &mut openssl::ssl::SslStream<std::net::TcpStream>,
) -> Result<(String, String, BTreeMap<String, String>, String), String> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|error| format!("the request line could not be read: {error}"))?;
    let mut parts = line.split_whitespace();
    let method = parts.next().ok_or("the request has no method")?.to_owned();
    let target = parts.next().ok_or("the request has no target")?.to_owned();

    let mut headers = BTreeMap::new();
    loop {
        let mut header = String::new();
        reader
            .read_line(&mut header)
            .map_err(|error| format!("a header could not be read: {error}"))?;
        let header = header.trim_end();
        if header.is_empty() {
            break;
        }
        if let Some((name, value)) = header.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
        }
    }

    let length: usize = headers
        .get("content-length")
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    let mut body = vec![0_u8; length];
    if length > 0 {
        reader
            .read_exact(&mut body)
            .map_err(|error| format!("the body could not be read: {error}"))?;
    }
    Ok((
        method,
        target,
        headers,
        String::from_utf8_lossy(&body).into_owned(),
    ))
}

fn write_json(
    stream: &mut openssl::ssl::SslStream<std::net::TcpStream>,
    status: u16,
    body: &str,
) -> Result<(), String> {
    let head = format!(
        "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(head.as_bytes())
        .and_then(|()| stream.write_all(body.as_bytes()))
        .and_then(|()| stream.flush())
        .map_err(|error| format!("the answer could not be written: {error}"))
}

/// One value out of a flat JSON object.
fn field(body: &str, name: &str) -> Option<String> {
    let marker = format!("\"{name}\":\"");
    let start = body.find(&marker)? + marker.len();
    let end = body[start..].find('"')? + start;
    Some(body[start..end].to_owned())
}

/// One value out of a query string.
fn query(target: &str, name: &str) -> Option<String> {
    let (_, query) = target.split_once('?')?;
    query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value.to_owned())
}

/// A certificate this server signs for itself.
fn self_signed(names: &[String], addresses: &[String]) -> Result<(X509, PKey<Private>), String> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
        .map_err(|error| format!("the curve is unavailable: {error}"))?;
    let key = EcKey::generate(&group).map_err(|error| format!("no key: {error}"))?;
    let key = PKey::from_ec_key(key).map_err(|error| format!("no key: {error}"))?;

    let mut subject = X509NameBuilder::new().map_err(|error| format!("no subject: {error}"))?;
    subject
        .append_entry_by_text("CN", names.first().map_or("localhost", String::as_str))
        .map_err(|error| format!("no subject: {error}"))?;
    let subject = subject.build();

    let mut builder = X509::builder().map_err(|error| format!("no certificate: {error}"))?;
    let mut serial = BigNum::new().map_err(|error| format!("no serial: {error}"))?;
    serial
        .rand(64, MsbOption::MAYBE_ZERO, false)
        .map_err(|error| format!("no serial: {error}"))?;
    let serial = serial
        .to_asn1_integer()
        .map_err(|error| format!("no serial: {error}"))?;
    builder
        .set_serial_number(&serial)
        .and_then(|()| builder.set_version(2))
        .and_then(|()| builder.set_subject_name(&subject))
        .and_then(|()| builder.set_issuer_name(&subject))
        .and_then(|()| builder.set_pubkey(&key))
        .map_err(|error| format!("the certificate could not be filled in: {error}"))?;

    let from = Asn1Time::days_from_now(0).map_err(|error| format!("no time: {error}"))?;
    let until = Asn1Time::days_from_now(1).map_err(|error| format!("no time: {error}"))?;
    builder
        .set_not_before(&from)
        .and_then(|()| builder.set_not_after(&until))
        .map_err(|error| format!("the validity could not be set: {error}"))?;

    builder
        .append_extension(
            BasicConstraints::new()
                .critical()
                .ca()
                .build()
                .map_err(|error| format!("no constraints: {error}"))?,
        )
        .map_err(|error| format!("no constraints: {error}"))?;

    let mut alternative = SubjectAlternativeName::new();
    for name in names {
        alternative.dns(name);
    }
    for address in addresses {
        alternative.ip(address);
    }
    let context = builder.x509v3_context(None, None);
    let alternative = alternative
        .build(&context)
        .map_err(|error| format!("no names: {error}"))?;
    builder
        .append_extension(alternative)
        .map_err(|error| format!("no names: {error}"))?;

    builder
        .sign(&key, MessageDigest::sha256())
        .map_err(|error| format!("the certificate could not be signed: {error}"))?;
    Ok((builder.build(), key))
}

fn read_arguments() -> Result<Told, String> {
    let mut listen = "0.0.0.0:8443".to_owned();
    let mut zone_id = String::new();
    let mut token_file = String::new();
    let mut dns_server = String::new();
    let mut dns_zone = String::new();
    let mut tsig_key = String::new();
    let mut tsig_secret_file = String::new();
    let mut cert_out = String::new();
    let mut names = Vec::new();
    let mut addresses = Vec::new();
    let mut no_dns = false;

    let mut arguments = std::env::args().skip(1);
    while let Some(flag) = arguments.next() {
        let mut value = || {
            arguments
                .next()
                .ok_or_else(|| format!("{flag} needs a value"))
        };
        match flag.as_str() {
            "--listen" => listen = value()?,
            "--zone-id" => zone_id = value()?,
            "--token-file" => token_file = value()?,
            "--dns-server" => dns_server = value()?,
            "--dns-zone" => dns_zone = value()?,
            "--tsig-key" => tsig_key = value()?,
            "--tsig-secret-file" => tsig_secret_file = value()?,
            "--cert-out" => cert_out = value()?,
            "--name" => names.push(value()?),
            "--address" => addresses.push(value()?),
            "--no-dns" => no_dns = true,
            other => return Err(format!("{other} is not an argument this takes")),
        }
    }

    for (name, held) in [
        ("--zone-id", &zone_id),
        ("--token-file", &token_file),
        ("--dns-server", &dns_server),
        ("--dns-zone", &dns_zone),
        ("--tsig-key", &tsig_key),
        ("--tsig-secret-file", &tsig_secret_file),
        ("--cert-out", &cert_out),
    ] {
        if held.is_empty() {
            return Err(format!("{name} is required"));
        }
    }

    let token = read_trimmed(&token_file)?;
    let tsig_secret = read_trimmed(&tsig_secret_file)?;

    let key_file = format!("{cert_out}.key.conf");
    std::fs::write(
        &key_file,
        format!(
            "key \"{tsig_key}\" {{\n    algorithm hmac-sha256;\n    secret \"{tsig_secret}\";\n}};\n"
        ),
    )
    .map_err(|error| format!("{key_file} could not be written: {error}"))?;

    Ok(Told {
        listen,
        zone_id,
        token,
        dns_server,
        dns_zone,
        key_file,
        cert_out,
        names,
        addresses,
        no_dns,
    })
}

fn read_trimmed(path: &str) -> Result<String, String> {
    std::fs::read_to_string(path)
        .map(|held| held.trim().to_owned())
        .map_err(|error| format!("{path} could not be read: {error}"))
}

fn flush() {
    let _ = std::io::stdout().flush();
}
