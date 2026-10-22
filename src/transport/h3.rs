//! Tier-1 HTTP/3 + QUIC transport (v4 phase 5.1).
//!
//! One Chrome-true boring context (see tls.rs) under the donsetch
//! fork of quiche 0.29.3. One QUIC connection serves one request in
//! this build: the agent's own fetch shape does not overlap streams,
//! so multiplexing inside one connection is an explicit v2 question,
//! not a silent one.
//!
//! Wire shape:
//! - TLS 1.3 only, h3 ALPN, Chrome's cipher/curve/sigalg/GREASE core
//!   (the same builder our h1/h2 path uses).
//! - QUIC transport params from Chrome's public defaults (v1; a
//!   byte-exact param capture is recorded in design/v4.md's edge
//!   ledger for the v2 parity pass).
//! - 0-RTT only when a serialized session exists in route memory; the
//!   config arms `enable_early_data` only when a ticket is present.
//!
//! Route policy lives in routes.rs: h3 only when the origin's alt-svc
//! vouched for it, no h3 behind a CONNECT proxy, DONSETCH_NO_H3 as the
//! hard kill switch.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;

use crate::error::FetchError;

pub use quiche::h3;
use quiche::h3::NameValue;

const PROTOCOL_VERSION: u32 = quiche::PROTOCOL_VERSION;
const UDP_BUF: usize = 65_527;

static QUIC_TOTAL_CONN: AtomicU64 = AtomicU64::new(0);

pub fn stats() -> u64 {
    QUIC_TOTAL_CONN.load(Ordering::Relaxed)
}

#[derive(Default, Debug)]
pub struct QuicStats {
    pub handshake_ms: u128,
    pub early_data: bool,
    pub resumed: bool,
    pub pkts_in: u64,
    pub pkts_out: u64,
    pub total_ms: u128,
}

pub struct H3Out {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub altsvc: Option<String>,
}

pub struct H3Request<'a> {
    pub egress: &'a str,
    pub host: &'a str,
    pub port: u16,
    pub path: &'a str,
    pub authority: &'a str,
    pub headers: Vec<(String, String)>,
    pub user_agent: &'a str,
    pub accept: &'a str,
    pub timeout: Duration,
}

/// Same bomb rule as the h1 reader: a body must fail the shared
/// transport cap BEFORE it allocates past it, not after.
fn accept_body_chunk(body: &mut Vec<u8>, chunk: &[u8]) -> Result<(), FetchError> {
    if body.len().saturating_add(chunk.len()) > super::MAX_BODY {
        return Err(FetchError::Http("h3: body exceeds cap".into()));
    }
    body.extend_from_slice(chunk);
    Ok(())
}

/// Blocking libc resolver, run OFF the reactor with the same 10s
/// bound the h1/h2 dial path uses: to_socket_addrs() can block for
/// the resolver's full timeout chain, and the h3 lane runs its loop
/// on a tokio worker.
async fn resolve_host_async(host: String, port: u16) -> Result<SocketAddr, FetchError> {
    // Shared cache, and the only resolver path in the h3 lane now: it
    // used to run its own blocking `to_socket_addrs` on a worker thread
    // with its own 10s timeout, so the guard, the h1/h2 connect and this
    // dial could each pay a separate round trip for one name.
    let addrs = crate::transport::dns::resolve(&host, port).await?;
    // Same connect-time SSRF filter the h1/h2 dial path applies
    // in tcp::happy_connect_with: resolve, then drop private /
    // loopback resolved IPs (unless the private-egress escape
    // hatch is on) before dialing. ensure_url_safe already
    // rejected private hosts at request time, but a DNS rebind
    // between that check and this dial would otherwise reach an
    // internal address over QUIC : h1/h2 re-filter here, h3 did
    // not. This closes the parity gap.
    select_dial_addr(addrs, crate::fetch::guards::private_egress_allowed(), &host)
}

/// Pick the address to dial from a resolved set, applying the same
/// SSRF filter the h1/h2 path uses at connect time. With private
/// egress allowed (the DONSETCH_ALLOW_PRIVATE_EGRESS escape hatch)
/// the first address is used as-is; otherwise the first PUBLIC
/// address is chosen, and a host that resolves ONLY to private /
/// loopback addresses is refused (a rebind at dial time cannot reach
/// an internal service over QUIC). Pure, so the filter is unit-tested
/// without a resolver.
fn select_dial_addr(
    addrs: Vec<SocketAddr>,
    allow_private: bool,
    label: &str,
) -> Result<SocketAddr, FetchError> {
    if allow_private {
        return addrs
            .into_iter()
            .next()
            .ok_or_else(|| FetchError::Dns(format!("resolve returned no addresses for {label}")));
    }
    if addrs.is_empty() {
        return Err(FetchError::Dns(format!(
            "resolve returned no addresses for {label}"
        )));
    }
    addrs
        .into_iter()
        .find(|a| !crate::fetch::guards::is_ssrf_resolved_ip(&a.ip()))
        .ok_or_else(|| {
            FetchError::Ssrf(format!(
                "{label} resolves to a private/loopback address : SSRF guard"
            ))
        })
}

/// All the quiche quoting for one connection: our Chrome-true builder
/// and Chrome's public default transport params. quiche Config is
/// single-use at connect time, so it is rebuilt per request.
fn quic_config(profile: &crate::profile::BrowserProfile) -> Result<quiche::Config, FetchError> {
    quic_config_with(profile, crate::transport::ca_blocklist::COMPROMISED_CA_KEYS)
}

/// `quic_config` with its own list of blocked SubjectPublicKeyInfo
/// SHA-256 hashes in place of the compromised-CA list.
#[cfg_attr(test, allow(clippy::map_unwrap_or))]
fn quic_config_with(
    profile: &crate::profile::BrowserProfile,
    blocked: &'static [[u8; 32]],
) -> Result<quiche::Config, FetchError> {
    let builder = crate::transport::tls::build_quic_ctx_builder(profile, blocked)?;
    // Never call cfg.verify_peer here: it replaces the builder's verify
    // callback with none, which drops the blocklist check, and
    // verify_peer(false) also turns verification off.
    // NOTE(quiche): quiche's Config map_err has clippy's map_err for
    // the small closure body; keep it because it shows the eventual
    // failure surface in one place.
    let cfg = quiche::Config::with_boring_ssl_ctx_builder(PROTOCOL_VERSION, builder)
        .map_err(|e| FetchError::Http(format!("quiche config init failed: {e}")))?;
    let mut cfg = cfg;
    // The boring ctx ALPN already sends the single h3 entry; this call
    // mirrors the negotiated ALPN inside quiche's own connection.
    cfg.set_application_protos(&[b"h3"])
        .map_err(|_| FetchError::Http("quiche alpn failed".into()))?;
    cfg.grease(true);
    cfg.set_max_idle_timeout(30_000);
    cfg.set_initial_max_data(6_291_456);
    cfg.set_initial_max_stream_data_bidi_local(1_048_576);
    cfg.set_initial_max_stream_data_bidi_remote(1_048_576);
    cfg.set_initial_max_stream_data_uni(1_048_576);
    cfg.set_initial_max_streams_bidi(100);
    cfg.set_initial_max_streams_uni(100);
    cfg.set_max_recv_udp_payload_size(65_527);
    cfg.set_max_send_udp_payload_size(1_352);
    cfg.discover_pmtu(true);
    Ok(cfg)
}

/// HTTP/3 forbids connection-specific fields and requires lowercase names
/// (RFC 9114 sections 4.2 and 4.2.2). Keep end-to-end fields unchanged.
fn request_fields(headers: &[(String, String)]) -> Vec<h3::Header> {
    let nominated: Vec<String> = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("connection"))
        .flat_map(|(_, value)| value.split(','))
        .map(|name| name.trim().to_ascii_lowercase())
        .collect();
    headers
        .iter()
        .filter_map(|(name, value)| {
            let name = name.to_ascii_lowercase();
            if name.starts_with(':')
                || matches!(
                    name.as_str(),
                    "connection"
                        | "proxy-connection"
                        | "keep-alive"
                        | "transfer-encoding"
                        | "upgrade"
                        | "host"
                )
                || nominated.contains(&name)
                || (name == "te" && !value.trim().eq_ignore_ascii_case("trailers"))
            {
                return None;
            }
            Some(h3::Header::new(name.as_bytes(), value.as_bytes()))
        })
        .collect()
}

pub async fn h3_fetch_heat(
    req: &H3Request<'_>,
    profile: &crate::profile::BrowserProfile,
) -> Result<(H3Out, QuicStats), FetchError> {
    h3_fetch_inner(
        req.egress,
        req.host,
        req.port,
        req.path,
        req.authority,
        req.headers.clone(),
        req.user_agent,
        req.accept,
        profile,
        req.timeout,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn h3_fetch_inner(
    egress: &str,
    host: &str,
    port: u16,
    path: &str,
    authority: &str,
    headers: Vec<(String, String)>,
    user_agent: &str,
    accept: &str,
    profile: &crate::profile::BrowserProfile,
    timeout: Duration,
) -> Result<(H3Out, QuicStats), FetchError> {
    let mut cfg = quic_config(profile)?;
    let peer = resolve_host_async(host.to_string(), port).await?;
    let socket = if peer.is_ipv4() {
        UdpSocket::bind("0.0.0.0:0").await?
    } else {
        UdpSocket::bind("[::]:0").await?
    };
    socket.connect(&peer).await?;
    let local_addr = socket.local_addr()?;

    // Ticket load: when there is one, arm 0-RTT (a ticket must exist
    // for the early-data to fire) and stamp it before quiche's first
    // packet leaves.
    let resumed = crate::transport::routes::load_h3_session(authority, egress);
    if let Some(bytes) = &resumed {
        if crate::config::cfg().debug.ghost {
            crate::diag!("[h3] session resume armed ({} bytes)", bytes.len());
        }
        cfg.enable_early_data();
    }

    // Long random local CID, Chrome-style local CIDs.
    let mut scid = [0u8; quiche::MAX_CONN_ID_LEN];
    boring::rand::rand_bytes(&mut scid)
        .map_err(|_| FetchError::Http("quic cid rand failed".into()))?;

    // quiche checks `host` as a DNS name only (X509_VERIFY_PARAM_set1_host).
    // An IP-literal origin therefore fails the check against a certificate
    // that names the address only as an IP SAN, and the fetch falls back to
    // h1/h2, whose boring connector checks an IP host as an IP.
    let mut conn = quiche::connect(
        Some(host),
        &quiche::ConnectionId::from_ref(&scid[..]),
        local_addr,
        peer,
        &mut cfg,
    )
    .map_err(|_| FetchError::Http("quic connect init failed".into()))?;
    if let Some(sess) = &resumed {
        conn.set_session(sess)
            .map_err(|_| FetchError::Http("quic session set failed".into()))?;
    }

    let started = Instant::now();
    let deadline = started + timeout;

    let mut req_headers = vec![
        h3::Header::new(b":method", b"GET"),
        h3::Header::new(b":scheme", b"https"),
        h3::Header::new(b":path", path.as_bytes()),
        h3::Header::new(b":authority", authority.as_bytes()),
        h3::Header::new(b"user-agent", user_agent.as_bytes()),
        h3::Header::new(b"accept", accept.as_bytes()),
    ];
    req_headers.extend(request_fields(&headers));

    let mut send_buf = vec![0u8; UDP_BUF];
    let mut recv_buf = vec![0u8; UDP_BUF];

    let mut h3conn: Option<h3::Connection> = None;
    let mut status = 0u16;
    let mut resp_headers: Vec<(String, String)> = Vec::new();
    let mut body: Vec<u8> = Vec::new();
    let mut altsvc: Option<String> = None;
    let mut request_sent = false;
    let mut pkts_in = 0u64;
    let mut pkts_out = 0u64;
    let mut handshake_ms = 0u128;
    let early_data = resumed.is_some();
    let mut rtt_landed = false;

    loop {
        // Flush quiche's outbound packets.
        loop {
            let (write, _info) = match conn.send(&mut send_buf) {
                Ok(v) => v,
                Err(quiche::Error::Done) => break,
                Err(e) => return Err(FetchError::Http(format!("quic send err {e}"))),
            };
            if write == 0 {
                break;
            }
            socket
                .send(&send_buf[..write])
                .await
                .map_err(|e| FetchError::Http(format!("udp send err {e}")))?;
            pkts_out += 1;
        }

        // Drain inbound until the socket reports WouldBlock / Done.
        loop {
            match socket.try_recv(&mut recv_buf) {
                Ok(n) if n > 0 => {
                    let info = quiche::RecvInfo {
                        from: peer,
                        to: local_addr,
                    };
                    match conn.recv(&mut recv_buf[..n], info) {
                        Ok(_) => {
                            pkts_in += 1;
                        }
                        Err(quiche::Error::Done) => break,
                        Err(e) => return Err(FetchError::Http(format!("quic recv err {e}"))),
                    }
                }
                Ok(_) => {}
                Err(kind)
                    if kind.kind() == std::io::ErrorKind::WouldBlock
                        || kind.kind() == std::io::ErrorKind::ConnectionAborted =>
                {
                    break;
                }
                Err(kind) if kind.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(kind) => return Err(FetchError::Http(format!("udp recv err {kind}"))),
            }
        }

        // Handshake done: the h3 layer can speak.
        if conn.is_established() && h3conn.is_none() {
            let h3cfg =
                h3::Config::new().map_err(|_| FetchError::Http("h3 config init failed".into()))?;
            h3conn = Some(
                h3::Connection::with_transport(&mut conn, &h3cfg)
                    .map_err(|_| FetchError::Http("h3 connect failed".into()))?,
            );
            handshake_ms = started.elapsed().as_millis();
            rtt_landed = early_data;
        }

        // Send our request once the h3 layer is live.
        if !request_sent && let Some(hc) = h3conn.as_mut() {
            hc.send_request(&mut conn, &req_headers, true)
                .map_err(|e| FetchError::Http(format!("h3 send err {e}")))?;
            request_sent = true;
        }

        let mut stream_done = false;
        if let Some(hc) = h3conn.as_mut() {
            loop {
                let (sid, event) = match hc.poll(&mut conn) {
                    Ok((sid, ev)) => (sid, ev),
                    Err(h3::Error::Done) => break,
                    Err(e) => return Err(FetchError::Http(format!("h3 poll err {e}"))),
                };
                match event {
                    h3::Event::Headers { list, .. } => {
                        // Early-hints (1xx) over h3 are informational:
                        // the final status and body follow on the same
                        // stream. Record alt-svc hints, keep polling. A
                        // 1xx is only treated as final if it is also
                        // the last... never: non-1xx always wins.
                        let is_informational = list.iter().any(|h| {
                            h.name() == b":status"
                                && std::str::from_utf8(h.value())
                                    .ok()
                                    .and_then(|x| x.trim().parse::<u16>().ok())
                                    .is_some_and(|s| s < 200)
                        });
                        if is_informational {
                            for hdr in &list {
                                let name = String::from_utf8_lossy(hdr.name()).to_ascii_lowercase();
                                if name == "alt-svc" {
                                    altsvc =
                                        Some(String::from_utf8_lossy(hdr.value()).into_owned());
                                }
                            }
                            continue;
                        }
                        for hdr in &list {
                            // HTTP/3 field names are lowercase on the
                            // wire; normalize a nonconforming peer's
                            // mixed-case names like the h1 reader does,
                            // so the downstream content-encoding /
                            // alt-svc lookups cannot be dodged.
                            let name = String::from_utf8_lossy(hdr.name()).to_ascii_lowercase();
                            let value = String::from_utf8_lossy(hdr.value()).into_owned();
                            if name == ":status" && status == 0 {
                                status = value.trim().parse::<u16>().unwrap_or(0);
                                continue;
                            }
                            if name == "alt-svc" {
                                altsvc = Some(value);
                                continue;
                            }
                            if !name.starts_with(':') {
                                resp_headers.push((name, value));
                            }
                        }
                    }
                    h3::Event::Data => {
                        let mut chunk = [0u8; 65_536];
                        loop {
                            match hc.recv_body(&mut conn, sid, &mut chunk) {
                                Ok(n) => accept_body_chunk(&mut body, &chunk[..n])?,
                                Err(h3::Error::Done) => break,
                                Err(e) => {
                                    return Err(FetchError::Http(format!("h3 body err {e}")));
                                }
                            }
                        }
                    }
                    h3::Event::Finished => stream_done = true,
                    h3::Event::Reset(..) => {
                        return Err(FetchError::Http("h3 stream reset".into()));
                    }
                    h3::Event::GoAway => {}
                    h3::Event::PriorityUpdate => {}
                }
            }
        }

        // Response landed: return it, and keep the fully-local
        // session for the next 0-RTT handshake on this origin. The
        // ticket usually lands within tens of ms of the response, so
        // hold the connection (Chrome-style) for a bounded window:
        // returning early means the next handshake loses 0-RTT.
        if stream_done {
            let hold_until = Instant::now() + Duration::from_millis(400);
            while conn.session().is_none() {
                let now = Instant::now();
                if now >= deadline || now >= hold_until {
                    break;
                }
                // Drain any pending inbound (the ticket may still be
                // on the wire) before the short sleep.
                loop {
                    match socket.try_recv(&mut recv_buf) {
                        Ok(n) if n > 0 => {
                            if conn
                                .recv(
                                    &mut recv_buf[..n],
                                    quiche::RecvInfo {
                                        from: peer,
                                        to: local_addr,
                                    },
                                )
                                .is_ok()
                            {
                                pkts_in += 1;
                            }
                        }
                        _ => break,
                    }
                }
                loop {
                    match conn.send(&mut send_buf) {
                        Ok((write, _)) if write > 0 => {
                            let _ = socket.send(&send_buf[..write]).await;
                        }
                        _ => break,
                    }
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            let _ = conn.close(true, 0, b"");
            if let Some(sess) = conn.session() {
                if crate::config::cfg().debug.ghost {
                    crate::diag!("[h3] session saved {} bytes", sess.len());
                }
                crate::transport::routes::save_h3_session(authority, egress, sess);
            } else if crate::config::cfg().debug.ghost {
                crate::diag!("[h3] no session ticket before close");
            }
            QUIC_TOTAL_CONN.fetch_add(1, Ordering::Relaxed);
            return Ok((
                H3Out {
                    status,
                    headers: resp_headers,
                    body: std::mem::take(&mut body),
                    altsvc,
                },
                QuicStats {
                    handshake_ms,
                    early_data: rtt_landed,
                    resumed: conn.is_resumed(),
                    pkts_in,
                    pkts_out,
                    total_ms: started.elapsed().as_millis(),
                },
            ));
        }

        // Give up when the QUIC shuts down pre-response, or after
        // headers but before the stream Finished. `stream_done` is
        // the only honest completion: a connection that closed or
        // drained early (idle timeout, hostile CONNECTION_CLOSE,
        // server death) carries a PARTIAL body, and returning it as
        // success once scored a truncated page clean and stored it
        // into the cache. Drop the route; h1/h2 answer instead.
        if conn.is_closed() || conn.is_draining() {
            if status != 0 {
                QUIC_TOTAL_CONN.fetch_add(1, Ordering::Relaxed);
            }
            return Err(FetchError::Http(format!(
                "h3: quic closed before stream finished (status {status}, {} body bytes)",
                body.len()
            )));
        }

        let now = Instant::now();
        if now >= deadline {
            return Err(FetchError::Http("quic deadline exceeded".into()));
        }
        match conn.timeout() {
            Some(t) => {
                let at = now + t;
                let wait = at
                    .saturating_duration_since(now)
                    .min(Duration::from_millis(20));
                tokio::time::sleep(wait).await;
                conn.on_timeout();
            }
            None => tokio::time::sleep(Duration::from_millis(5)).await,
        }
    }
}

/// The fetch client's h3 route (v4 phase 5.1): a direct-egress-only
/// quic/h3 attempt over the same Chrome-true builder the h1/h2 path
/// uses. `user_headers` arrive already profile-shaped (the same header
/// set the h1/h2 path builds), so the wire stays coherent across the
/// transports. No 0-RTT on force: force is an explicit re-handshake
/// unless route memory vouches a session, and that is the caller's
/// argument for `session`.
#[allow(clippy::too_many_arguments)]
pub async fn h3_fetch_direct(
    host: &str,
    port: u16,
    path: &str,
    authority: &str,
    user_headers: Vec<(String, String)>,
    timeout: Option<Duration>,
    profile: &crate::profile::BrowserProfile,
) -> Result<(H3Out, QuicStats), FetchError> {
    if crate::config::cfg().debug.ghost {
        crate::diag!("[h3] attempt {host}:{port}{path}");
    }
    let timeout = timeout.unwrap_or(Duration::from_secs(15));
    let accept = user_headers
        .iter()
        .find(|(n, _)| n == "accept")
        .map(|(_, v)| v.clone())
        .unwrap_or_else(|| "text/html,application/xhtml+xml".into());
    let user_agent = user_headers
        .iter()
        .find(|(n, _)| n == "user-agent")
        .map(|(_, v)| v.clone())
        .unwrap_or_default();
    let req = H3Request {
        egress: "direct",
        host,
        port,
        path,
        authority,
        headers: user_headers
            .iter()
            .filter(|(n, _)| n != "user-agent" && n != "accept")
            .cloned()
            .collect(),
        user_agent: user_agent.as_str(),
        accept: accept.as_str(),
        timeout,
    };
    let (out, stats) = h3_fetch_heat(&req, profile).await?;
    if crate::config::cfg().debug.ghost {
        crate::diag!(
            "[h3] stats {}:{} early={} resumed={} hs_ms={} total_ms={} pkts_in={} pkts_out={}",
            host,
            port,
            stats.early_data,
            stats.resumed,
            stats.handshake_ms,
            stats.total_ms,
            stats.pkts_in,
            stats.pkts_out
        );
    }
    Ok((out, stats))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_fields_drop_http1_connection_metadata() {
        let fields = [
            ("Connection", "keep-alive, X-Hop"),
            ("X-Hop", "private"),
            ("Keep-Alive", "timeout=5"),
            ("Proxy-Connection", "keep-alive"),
            ("Transfer-Encoding", "chunked"),
            ("Upgrade", "h2c"),
            ("Host", "example.test"),
            ("TE", "gzip"),
            ("Cookie", "session=value"),
            ("Authorization", "Bearer value"),
            ("X-End-To-End", "preserved"),
            ("te", "trailers"),
        ]
        .map(|(name, value)| (name.to_string(), value.to_string()));
        let sent = request_fields(&fields)
            .into_iter()
            .map(|field| {
                (
                    String::from_utf8(field.name().to_vec()).unwrap(),
                    String::from_utf8(field.value().to_vec()).unwrap(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            sent,
            vec![
                ("cookie".into(), "session=value".into()),
                ("authorization".into(), "Bearer value".into()),
                ("x-end-to-end".into(), "preserved".into()),
                ("te".into(), "trailers".into()),
            ]
        );
    }

    // The h3 dial path must apply the same connect-time SSRF filter
    // as h1/h2: a host that resolves to a private/loopback address
    // (a DNS rebind after the request-time check) must not be dialed
    // over QUIC. Pins the resolved-address selection.
    #[test]
    fn select_dial_addr_filters_private_resolved_ips() {
        let public: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let meta: SocketAddr = "169.254.169.254:443".parse().unwrap();
        let loop_: SocketAddr = "127.0.0.1:443".parse().unwrap();

        // A public address is chosen even when a private one is listed first.
        assert_eq!(
            select_dial_addr(vec![meta, public], false, "h").unwrap(),
            public
        );
        // Resolves only to private/loopback -> refused (SSRF guard).
        assert!(select_dial_addr(vec![meta, loop_], false, "h").is_err());
        // Empty resolution -> the honest name failure, not a guard error.
        let err = select_dial_addr(vec![], false, "h").unwrap_err();
        assert!(
            matches!(err, FetchError::Dns(_)),
            "an empty resolution is a name failure, not a policy block: {err:?}"
        );
        // The escape hatch takes the first address as-is (local egress).
        assert_eq!(
            select_dial_addr(vec![loop_, public], true, "h").unwrap(),
            loop_
        );
    }

    // The h1 reader learned this the hard way (#144): a hostile
    // origin streaming an unbounded body must hit the shared cap,
    // not the allocator. The h3 lane reads the same kind of wire.
    #[test]
    fn body_chunks_stop_at_the_shared_transport_cap() {
        let mut body = Vec::new();
        assert!(accept_body_chunk(&mut body, &[0u8; 65_536]).is_ok());
        assert_eq!(body.len(), 65_536);
        // Jump to just under the cap, then cross it.
        let mut near = vec![0u8; super::super::MAX_BODY - 10];
        assert!(accept_body_chunk(&mut near, &[0u8; 10]).is_ok());
        let before = near.len();
        assert!(
            accept_body_chunk(&mut near, &[0u8; 1]).is_err(),
            "the crossing chunk must fail"
        );
        assert_eq!(near.len(), before, "a refused chunk must not allocate");
    }

    /// A self-signed certificate for `host` with its own subject name, so
    /// chain building never mistakes one test certificate for another's
    /// issuer.
    fn own_cert(subject: &str, host: &str) -> rcgen::CertifiedKey<rcgen::KeyPair> {
        let signing_key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec![host.to_string()]).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, subject);
        let cert = params.self_signed(&signing_key).unwrap();
        rcgen::CertifiedKey { cert, signing_key }
    }

    /// Runs one QUIC handshake against an in-memory server presenting
    /// `server_cert`, with packets passed by hand: no socket, so no
    /// egress guard. `Ok(())` when the client completes it without an
    /// error; otherwise the transport error code the client closed with,
    /// whether or not the handshake had completed. Panics when the client
    /// has no transport error of its own: a stall, a close by the server,
    /// or an application error.
    fn handshake(
        client_cfg: &mut quiche::Config,
        server_cert: &rcgen::CertifiedKey<rcgen::KeyPair>,
    ) -> Result<(), u64> {
        use boring::ssl::{SslContext, SslMethod, SslVersion};

        let mut tls = SslContext::builder(SslMethod::tls()).unwrap();
        tls.set_min_proto_version(Some(SslVersion::TLS1_3)).unwrap();
        tls.set_max_proto_version(Some(SslVersion::TLS1_3)).unwrap();
        tls.set_certificate(&boring::x509::X509::from_der(server_cert.cert.der()).unwrap())
            .unwrap();
        tls.set_private_key(
            &boring::pkey::PKey::private_key_from_der(&server_cert.signing_key.serialize_der())
                .unwrap(),
        )
        .unwrap();
        let mut server_cfg =
            quiche::Config::with_boring_ssl_ctx_builder(PROTOCOL_VERSION, tls).unwrap();
        server_cfg.set_application_protos(&[b"h3"]).unwrap();

        let client_addr: SocketAddr = "127.0.0.1:40000".parse().unwrap();
        let server_addr: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let mut client = quiche::connect(
            Some("localhost"),
            &quiche::ConnectionId::from_ref(&[1; 16]),
            client_addr,
            server_addr,
            client_cfg,
        )
        .unwrap();
        let mut server = None;
        let mut buf = vec![0u8; UDP_BUF];
        for _ in 0..16 {
            loop {
                let len = match client.send(&mut buf) {
                    Ok((len, _)) => len,
                    Err(quiche::Error::Done) => break,
                    Err(e) => panic!("client send: {e:?}"),
                };
                let conn: &mut quiche::Connection = server.get_or_insert_with(|| {
                    quiche::accept(
                        &quiche::ConnectionId::from_ref(&[2; 16]),
                        None,
                        server_addr,
                        client_addr,
                        &mut server_cfg,
                    )
                    .unwrap()
                });
                // The server's own errors show up as the client's peer error.
                let _ = conn.recv(
                    &mut buf[..len],
                    quiche::RecvInfo {
                        from: client_addr,
                        to: server_addr,
                    },
                );
            }
            if let Some(conn) = server.as_mut() {
                loop {
                    let len = match conn.send(&mut buf) {
                        Ok((len, _)) => len,
                        Err(quiche::Error::Done) => break,
                        Err(e) => panic!("server send: {e:?}"),
                    };
                    // A refused certificate fails here and closes the client.
                    let _ = client.recv(
                        &mut buf[..len],
                        quiche::RecvInfo {
                            from: server_addr,
                            to: client_addr,
                        },
                    );
                }
            }
            if client.is_established() || client.local_error().is_some() {
                break;
            }
        }
        match (client.is_established(), client.local_error()) {
            (true, None) => Ok(()),
            (_, Some(e)) if !e.is_app => Err(e.error_code),
            (established, local) => panic!(
                "no client-side verdict: established={established}, local={local:?}, peer={:?}",
                client.peer_error()
            ),
        }
    }

    /// Clears the test's trust bundle from the environment and the disk,
    /// also when an assertion fails.
    struct TrustBundle(std::path::PathBuf);

    impl Drop for TrustBundle {
        fn drop(&mut self) {
            unsafe { std::env::remove_var("SSL_CERT_FILE") };
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    // The QUIC client accepted any server certificate: it checked
    // neither the trust store nor the host name, and the compromised-CA
    // list never reached it (GHSA-h25m-wq9j-hq58). The trusted localhost
    // server is the control: the same config completes the handshake
    // with it. Each refusal is pinned to the alert its own check sends,
    // so a refusal for another reason fails the test.
    #[test]
    fn quic_handshakes_verify_the_server_certificate() {
        // RFC 9001 section 4.8: a TLS alert closes a QUIC connection with
        // 0x100 plus the alert number (RFC 8446 section 6).
        const CRYPTO_ERROR: u64 = 0x100;
        const HANDSHAKE_FAILURE: u64 = 40;
        const BAD_CERTIFICATE: u64 = 42;
        const UNKNOWN_CA: u64 = 48;

        let trusted = own_cert("donsetch trusted", "localhost");
        let untrusted = own_cert("donsetch untrusted", "localhost");
        let other_host = own_cert("donsetch other host", "wrong.example");
        // Not under cache_dir(): an exported DONSETCH_CACHE_DIR would put
        // the bundle in a shared cache that outlives the run.
        let directory = std::env::temp_dir()
            .join("donsetch-test")
            .join(crate::handles::random_base62(16));
        std::fs::create_dir_all(&directory).unwrap();
        let _cleanup = TrustBundle(directory.clone());
        let bundle = directory.join("trusted.pem");
        std::fs::write(
            &bundle,
            format!("{}{}", trusted.cert.pem(), other_host.cert.pem()),
        )
        .unwrap();
        // Nextest isolates this owned trust bundle from every other test.
        unsafe {
            std::env::set_var("SSL_CERT_FILE", &bundle);
            std::env::remove_var("SSL_CERT_DIR");
        }

        let profile = crate::profile::BrowserProfile::chrome_150(crate::profile::Platform::Linux);
        let result = handshake(&mut quic_config(&profile).unwrap(), &trusted);
        assert_eq!(
            result,
            Ok(()),
            "the trusted localhost certificate must pass"
        );
        let result = handshake(&mut quic_config(&profile).unwrap(), &untrusted);
        assert_eq!(
            result,
            Err(CRYPTO_ERROR + UNKNOWN_CA),
            "an untrusted certificate must fail the trust check"
        );
        let result = handshake(&mut quic_config(&profile).unwrap(), &other_host);
        assert_eq!(
            result,
            Err(CRYPTO_ERROR + BAD_CERTIFICATE),
            "a certificate for another host must fail the host name check"
        );

        let trusted_key = boring::x509::X509::from_der(trusted.cert.der())
            .unwrap()
            .public_key()
            .unwrap()
            .public_key_to_der()
            .unwrap();
        let blocked: &'static [[u8; 32]] = Box::leak(Box::new([boring::sha::sha256(&trusted_key)]));
        let result = handshake(&mut quic_config_with(&profile, blocked).unwrap(), &trusted);
        // The blocklist callback's APPLICATION_VERIFICATION maps to this
        // alert; the trust store alone accepts this chain (control above).
        assert_eq!(
            result,
            Err(CRYPTO_ERROR + HANDSHAKE_FAILURE),
            "a blocked key must fail a trusted chain"
        );
    }
}
