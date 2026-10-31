//! HTTP transport for the MCP server.
//!
//! POST /mcp speaks JSON-RPC 2.0 exactly like stdio: every request is
//! dispatched through the same daemon handler, so initialize
//! negotiation, tools/list and full tool calls behave identically on
//! both transports. GET /health is a liveness probe for orchestrators
//! and load balancers.
//!
//! GET /mcp opens the server-initiated SSE stream that streamable-HTTP
//! clients expect after initialize (OpenCode among them fails the whole
//! connection on a bare 405 here). DonSeTch never pushes unsolicited
//! messages : no server tools, no sampling requests : so the stream
//! carries keep-alive comments only. It self-terminates just inside
//! SESSION_TTL: graceful shutdown is never blocked by an idle stream,
//! clients simply reconnect per SSE convention, and each reconnect
//! refreshes the session's idle timer. DELETE /mcp terminates a session
//! per the spec.
//!
//! Sessions: the server assigns an `Mcp-Session-Id` response header on
//! `initialize`. Clients that echo it back get a dedicated cancellation
//! registry, so a `notifications/cancelled` posted while a tool call is
//! in flight reaches it (mirroring stdio's shared registry). Clients
//! that ignore sessions : curl, simple integrators : share one default
//! registry; cancellation still works, they just share a request-id
//! namespace with other session-less clients. Unknown or expired
//! session ids get a 404, per the MCP streamable-HTTP convention.
//!
//! Hardening: optional bearer auth via `DONSETCH_HTTP_TOKEN`, a
//! configurable per-request timeout via `DONSETCH_HTTP_TIMEOUT_SECS`
//! (default 300), and JSON-RPC error envelopes for malformed bodies.
//! The server drains in-flight requests on SIGTERM/SIGINT before
//! shutting the daemon down.

use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::atomic::{AtomicI64, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::{
    Json, Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    response::{
        IntoResponse, Response,
        sse::{Event, KeepAlive, Sse},
    },
    routing::{get, post},
};
use futures_util::Stream;
use serde_json::{Value, json};
use tokio::sync::mpsc;
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};

use crate::mcp::server::{CancelMap, Daemon, cancel_key, handle};
use crate::mcp::wall_guard::{Outcome, WallGuard, WallGuardConfig};

/// Idle sessions are dropped after this long, so cancelled-tool
/// registries cannot leak forever for clients that vanish mid-call.
const SESSION_TTL: Duration = Duration::from_secs(30 * 60);
/// Upper bound on tracked sessions; the oldest are evicted beyond it.
const MAX_SESSIONS: usize = 1024;
/// Default per-request timeout when DONSETCH_HTTP_TIMEOUT_SECS is unset.
/// Historical default; the live default lives in config ([transport]
/// timeout_secs).
#[allow(dead_code)]
const DEFAULT_TIMEOUT_SECS: u64 = 300;
/// The GET /mcp SSE stream closes itself after this long (just inside
/// SESSION_TTL): an unbounded idle stream would hold graceful shutdown
/// open forever, and a closed stream is a routine reconnect for SSE
/// clients : one that usefully refreshes the session idle timer.
const SSE_MAX_LIFETIME: Duration = Duration::from_secs(25 * 60);

struct Session {
    cancels: CancelMap,
    /// Issue #27 compat mode for this session: set by the session's
    /// `initialize` handshake, read by every tool call it makes.
    mode: Arc<crate::mcp::compat::ModeCell>,
    last_seen: Instant,
}

/// Session-id → cancellation-registry table with idle-TTL GC and a
/// bounded size. Split out of the server state so the registry logic
/// can be tested without constructing a Daemon.
struct SessionTable {
    sessions: Mutex<HashMap<String, Session>>,
}

/// Shared HTTP server state.
#[derive(Clone)]
struct HttpState {
    daemon: Arc<Daemon>,
    sessions: Arc<SessionTable>,
    /// When set, requests must carry `Authorization: Bearer ***
    auth_token: Option<String>,
    timeout: Duration,
    cors_enabled: bool,
    bound: Bound,
    wall_guard: Arc<WallGuard>,
    in_flight: Arc<AtomicI64>,
}

/// Run the HTTP MCP server until SIGTERM/SIGINT.
pub async fn run(host: String, port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let t = crate::config::cfg().transport.clone();
    let auth_token = crate::config::configured_http_token(&t.token).map(str::to_owned);
    let auth_enabled = auth_token.is_some();
    let timeout = Duration::from_secs(t.timeout_secs);

    // CORS is off by default: MCP clients are processes, not browsers,
    // and a permissive layer would let any webpage open in a local
    // browser POST to a localhost instance and read the responses.
    // Browser-based clients can opt in with [transport] cors = true.
    let cors_enabled = t.cors;
    validate_http_config(cors_enabled, auth_enabled)?;

    // Configuration must fail before daemon construction starts background
    // work or touches persistent state.
    let daemon = Arc::new(Daemon::new().await.map_err(|e| e.to_string())?);
    daemon.start_prober();

    // Initialize wall guard from environment
    let notify_shutdown = Arc::new(tokio::sync::Notify::new());
    let wall_guard_config = WallGuardConfig::from_env();
    let wall_guard = if wall_guard_config.is_enabled() {
        WallGuard::new(wall_guard_config.clone(), Arc::clone(&notify_shutdown))
    } else {
        WallGuard::disabled()
    };

    let state = HttpState {
        daemon: Arc::clone(&daemon),
        sessions: Arc::new(SessionTable {
            sessions: Mutex::new(HashMap::new()),
        }),
        auth_token,
        timeout,
        cors_enabled,
        bound: Bound::new(&host, port),
        wall_guard,
        in_flight: Arc::new(AtomicI64::new(0)),
    };

    let app = Router::new()
        .route("/health", get(health_handler))
        .route("/ready", get(ready_handler))
        .route(
            "/mcp",
            post(mcp_handler).get(sse_handler).delete(delete_handler),
        )
        .layer(TraceLayer::new_for_http());
    let app = if cors_enabled {
        app.layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        )
    } else {
        app
    };
    let app = app.with_state(state);

    let listener = tokio::net::TcpListener::bind((host.as_str(), port)).await?;
    if auth_enabled {
        crate::diag!("[mcp] HTTP server listening on http://{host}:{port} (bearer auth enabled)");
    } else {
        crate::diag!("[mcp] HTTP server listening on http://{host}:{port}");
    }

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal(notify_shutdown))
        .await?;

    // Drain done; stop the daemon so no orphan browsers survive.
    crate::diag!("[mcp] draining complete, shutting daemon down");
    daemon.shutdown().await;
    Ok(())
}

/// Resolve SIGTERM/SIGINT into a future that completes on either, or wall_guard eviction.
async fn shutdown_signal(notify_shutdown: Arc<tokio::sync::Notify>) {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
        _ = notify_shutdown.notified() => {},
    }
    crate::diag!("[mcp] shutdown signal received; draining in-flight requests");
}

/// Liveness probe for orchestrators and load balancers.
async fn health_handler() -> impl IntoResponse {
    Json(json!({ "status": "ok", "transport": "http" }))
}

/// Readiness probe: returns 503 when instance is burned.
async fn ready_handler(State(state): State<HttpState>) -> impl IntoResponse {
    let status = state.wall_guard.ready_status();
    if status.burned {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "status": "burned",
                "total_walls": status.total_walls,
                "evictions": status.eviction_count,
            })),
        )
    } else {
        (StatusCode::OK, Json(json!({"status": "ready"})))
    }
}

/// Refuse the classic "localhost server + permissive CORS = drive-by"
/// footgun: `DONSETCH_HTTP_CORS` and `DONSETCH_HTTP_TOKEN` are
/// independently optional, so nothing stopped a user from enabling
/// permissive CORS (any origin) while leaving auth off. With that
/// combination, any webpage open in the same local browser could
/// POST arbitrary MCP tool calls (fetch/crawl/search, including the
/// `actions` browser-automation surface) to this server with no
/// authentication. Fail closed instead of just warning: a startup
/// error is impossible to miss, unlike an crate::diag! in a background
/// daemon's log.
fn validate_http_config(cors_enabled: bool, auth_enabled: bool) -> Result<(), String> {
    if cors_enabled && !auth_enabled {
        return Err(
            "DONSETCH_HTTP_CORS is enabled without DONSETCH_HTTP_TOKEN: any \
             webpage open in a local browser could drive this MCP server \
             with no authentication. Set DONSETCH_HTTP_TOKEN to a random \
             secret before enabling CORS, or leave DONSETCH_HTTP_CORS unset \
             if you don't need browser-based clients."
                .into(),
        );
    }
    Ok(())
}

/// Where the server listens, as the request checks need it.
#[derive(Clone, Debug)]
struct Bound {
    loopback: bool,
    port: u16,
}

impl Bound {
    fn new(host: &str, port: u16) -> Self {
        Self {
            loopback: is_loopback_name(host),
            port,
        }
    }
}

/// True for the names a loopback server answers to: `localhost`,
/// `127.0.0.1` (any 127/8 literal), `::1`, with or without brackets.
fn is_loopback_name(host: &str) -> bool {
    let h = host.trim().trim_start_matches('[').trim_end_matches(']');
    if h.eq_ignore_ascii_case("localhost") || h == "::1" {
        return true;
    }
    h.parse::<std::net::Ipv4Addr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
        || h.parse::<std::net::Ipv6Addr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false)
}

/// Splits `host[:port]` as it appears in a Host header or an Origin
/// authority, bracketed IPv6 included. `None` when the port is not a
/// number.
fn split_host_port(authority: &str) -> Option<(&str, Option<u16>)> {
    let a = authority.trim();
    if let Some(rest) = a.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = &rest[..end];
        return match &rest[end + 1..] {
            "" => Some((host, None)),
            p => Some((host, Some(p.strip_prefix(':')?.parse().ok()?))),
        };
    }
    match a.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => Some((host, Some(port.parse().ok()?))),
        _ => Some((a, None)),
    }
}

/// The request checks that run before auth on every /mcp route.
///
/// - `Origin`: a browser sets it on every cross-site request, a
///   native MCP client never does. With CORS off (auth may be off
///   too) only a loopback page is admitted; CORS mode, which
///   `validate_http_config` allows only with auth, admits any.
/// - `Host`: a server bound to loopback answers only to loopback
///   names on its own port, so a page whose name resolves to
///   127.0.0.1 (DNS rebinding) is refused; a request without a Host
///   header is not a browser's; a server the operator bound to a
///   reachable address answers to any name.
///
/// `Err` carries the word for the refusal.
fn request_allowed(
    headers: &HeaderMap,
    cors_enabled: bool,
    bound: &Bound,
) -> Result<(), &'static str> {
    if let Some(origin) = headers.get("origin") {
        let origin = origin.to_str().unwrap_or("");
        let loopback_origin = origin
            .split_once("://")
            .and_then(|(_, rest)| split_host_port(rest))
            .is_some_and(|(host, _)| is_loopback_name(host));
        if !cors_enabled && !loopback_origin {
            return Err("origin not allowed");
        }
    }
    // A browser always sends Host and a rebound name needs one, so
    // only a Host that is present and foreign is refused.
    if bound.loopback
        && let Some(raw) = headers.get("host")
    {
        let Some((host, port)) = raw.to_str().ok().and_then(split_host_port) else {
            return Err("host not allowed");
        };
        if !is_loopback_name(host) || port.is_some_and(|p| p != bound.port) {
            return Err("host not allowed");
        }
    }
    Ok(())
}

/// Consumes a tool call's progress lines for the life of the call.
///
/// The HTTP transport has nowhere to deliver progress (a POST gets
/// one response), but the tool's forwarder still sends every line
/// into the bounded channel and `handle` awaits that forwarder after
/// the tool returns. Without a reader, the 257th line blocked the
/// forwarder, the await never finished, and a call that had
/// completed timed out. Drained here from the start instead.
fn spawn_progress_sink(mut rx: mpsc::Receiver<String>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move { while rx.recv().await.is_some() {} })
}

/// Bearer-auth check shared by every /mcp method (health stays open).
fn authorized(state: &HttpState, headers: &HeaderMap) -> bool {
    token_ok(state.auth_token.as_deref(), headers)
}

/// Pure form of the bearer check so tests don't need server state.
fn token_ok(expected: Option<&str>, headers: &HeaderMap) -> bool {
    let Some(expected) = expected else {
        return true; // no token configured: auth is off
    };
    match headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    {
        Some(presented) => constant_time_eq(presented.as_bytes(), expected.as_bytes()),
        None => false,
    }
}

/// Constant-time equality (XOR fold, no early exit on the bytes). The
/// length check up front is deliberate: token length is not a secret
/// worth protecting, and folding equal-length buffers without a
/// byte-wise early exit removes the timing oracle on the token itself.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// A stream that stays silent for `max` and then ends. While silent, the
/// SSE body emits keep-alive comments; ending triggers the client's
/// routine reconnect.
fn silent_stream(max: Duration) -> impl Stream<Item = Result<Event, Infallible>> {
    futures_util::stream::unfold((), move |()| async move {
        tokio::time::sleep(max).await;
        None
    })
}

/// Server-initiated stream half of the streamable-HTTP transport.
///
/// DonSeTch has nothing server-initiated to say, so this exists purely
/// so clients that open the stream after initialize (per spec they MAY)
/// get a live SSE connection instead of a 405 that some clients :
/// OpenCode notably : treat as fatal. See the module docs for the
/// lifetime/reconnect reasoning.
async fn sse_handler(State(state): State<HttpState>, headers: HeaderMap) -> Response {
    if request_allowed(&headers, state.cors_enabled, &state.bound).is_err() {
        return StatusCode::FORBIDDEN.into_response();
    }
    if !authorized(&state, &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    // Unknown or expired session ids get a 404, per the same convention
    // as POST. No header (curl, plain probes) opens an anonymous stream.
    if let Some(sid) = headers.get("mcp-session-id").and_then(|v| v.to_str().ok())
        && !sid.is_empty()
        && state.sessions.registry(sid).is_none()
    {
        return StatusCode::NOT_FOUND.into_response();
    }
    Sse::new(silent_stream(SSE_MAX_LIFETIME))
        .keep_alive(
            KeepAlive::new()
                .interval(Duration::from_secs(15))
                .text("keep-alive"),
        )
        .into_response()
}

/// Session termination: drop the cancellation registry so a vanished
/// client's entry cannot linger until the idle TTL collects it.
async fn delete_handler(State(state): State<HttpState>, headers: HeaderMap) -> Response {
    if request_allowed(&headers, state.cors_enabled, &state.bound).is_err() {
        return StatusCode::FORBIDDEN.into_response();
    }
    if !authorized(&state, &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let status = match headers
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
    {
        Some(sid) => {
            let removed = state.sessions.remove(sid);
            if removed {
                StatusCode::NO_CONTENT
            } else {
                StatusCode::NOT_FOUND
            }
        }
        None => StatusCode::NO_CONTENT, // nothing to terminate
    };
    status.into_response()
}

fn rpc_error(status: StatusCode, code: i32, message: &str) -> Response {
    (
        status,
        Json(json!({
            "jsonrpc": "2.0",
            "id": null,
            "error": { "code": code, "message": message }
        })),
    )
        .into_response()
}

/// Generate an opaque, unguessable session id: 16 base62 chars (~95
/// bits) from the same entropy pool as handle IDs. Sequential or
/// timestamp-derived ids would let a client guess other sessions' ids;
/// the id is not itself an auth token, but unpredictability costs
/// nothing and removes the question.
fn new_session_id() -> String {
    crate::handles::random_base62(16)
}

impl SessionTable {
    /// Registry for an existing session id, or None if unknown.
    fn registry(&self, id: &str) -> Option<CancelMap> {
        self.session_handles(id).map(|(c, _)| c)
    }

    /// Cancels + mode cell for an existing session, refreshing idle.
    fn session_handles(&self, id: &str) -> Option<(CancelMap, Arc<crate::mcp::compat::ModeCell>)> {
        let mut sessions = self
            .sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.gc_locked(&mut sessions);
        let s = sessions.get_mut(id)?;
        s.last_seen = Instant::now();
        Some((Arc::clone(&s.cancels), Arc::clone(&s.mode)))
    }

    /// Registry + mode cell for `id`, creating it on first use. The
    /// empty id is the shared default registry for session-less
    /// clients; it is never a candidate for MAX_SESSIONS eviction.
    fn registry_or_create(&self, id: &str) -> (CancelMap, Arc<crate::mcp::compat::ModeCell>) {
        let mut sessions = self
            .sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.gc_locked(&mut sessions);
        if let Some(s) = sessions.get_mut(id) {
            s.last_seen = Instant::now();
            return (Arc::clone(&s.cancels), Arc::clone(&s.mode));
        }
        if sessions.len() >= MAX_SESSIONS && !id.is_empty() {
            // Evict the oldest session to bound memory.
            if let Some(oldest) = sessions
                .iter()
                .filter(|(k, _)| !k.is_empty())
                .min_by_key(|(_, s)| s.last_seen)
                .map(|(k, _)| k.clone())
            {
                sessions.remove(&oldest);
            }
        }
        let cancels: CancelMap = Arc::new(Mutex::new(HashMap::new()));
        let mode = Arc::new(crate::mcp::compat::ModeCell::new());
        sessions.insert(
            id.to_string(),
            Session {
                cancels: Arc::clone(&cancels),
                mode: Arc::clone(&mode),
                last_seen: Instant::now(),
            },
        );
        (cancels, mode)
    }

    /// Remove a session; true if it existed.
    fn remove(&self, id: &str) -> bool {
        self.sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(id)
            .is_some()
    }

    /// Drop sessions idle beyond TTL. Called with the lock held.
    fn gc_locked(&self, sessions: &mut HashMap<String, Session>) {
        self.gc_locked_with(sessions, SESSION_TTL);
    }

    /// TTL-parameterized form so tests can sweep with a tiny window
    /// (production TTLs are longer than a fresh host's uptime, which
    /// makes backdating an `Instant` by the real TTL unrepresentable).
    fn gc_locked_with(&self, sessions: &mut HashMap<String, Session>, ttl: Duration) {
        sessions.retain(|_, s| s.last_seen.elapsed() < ttl);
    }
}

impl HttpState {
    /// Registry + mode for session-less clients; created on first use.
    fn default_handles(&self) -> (CancelMap, Arc<crate::mcp::compat::ModeCell>) {
        self.sessions.registry_or_create("")
    }
}

/// Guard to automatically decrement in-flight counter on drop.
struct InFlightGuard {
    in_flight: Arc<AtomicI64>,
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.in_flight.fetch_sub(1, AtomicOrdering::SeqCst);
    }
}

/// Extract tool name and URL from a web_fetch request if applicable.
fn extract_web_fetch_info(req: &Value) -> Option<(String, String)> {
    let method = req.get("method").and_then(Value::as_str)?;
    if method != "tools/call" {
        return None;
    }
    let tool_name = req
        .get("params")
        .and_then(|p| p.get("name"))
        .and_then(Value::as_str)?;
    if tool_name != "web_fetch" {
        return None;
    }
    let url = req
        .get("params")
        .and_then(|p| p.get("arguments"))
        .and_then(|a| a.get("url"))
        .and_then(Value::as_str)?;
    Some((tool_name.to_string(), url.to_string()))
}

/// Extract outcome from a JSON-RPC tool-call response.
///
/// The production server wraps every tool result as:
///   {"jsonrpc":"2.0","id":..,"result":{...}}
///
/// Failure shape (real capture):
///   result.code = "network.dns" (or any wall/non-wall code)
///   result.errorKind = "permanent"
///   result.isError = false (always; tool errors are returned results, not throws)
///   result.content = [{"type":"text","text":"[meta] ..."}]
///
/// Success shape (real capture):
///   result._meta = {"com.donsetch/fetch-debug": {"elapsed_ms":113,"status":200,...}}
///   result.content = [{"type":"text","text":"<html...>"}]
///   (NO result.code, NO result.errorKind)
///
/// Rule:
///   WallBlocking: result.code is wall.challenge, wall.challenge_unsolved, or wall.blocked
///   Success:      result present, no result.code, result.isError is not true
///   Neutral:      any other shape (other code, unknown envelope, unparseable)
fn extract_outcome(resp_str: &str) -> Option<Outcome> {
    let resp: Value = serde_json::from_str(resp_str).ok()?;

    // Must be a JSON-RPC result envelope (not an error envelope)
    let result = resp.get("result")?;

    // Primary signal: result.code
    if let Some(code) = result.get("code").and_then(Value::as_str) {
        // Blocking walls trigger eviction
        if code == "wall.challenge" || code == "wall.challenge_unsolved" || code == "wall.blocked" {
            return Some(Outcome::WallBlocking);
        }
        // Any other code (network.dns, deadline.hit, wall.paywall, ...) is Neutral
        return Some(Outcome::Neutral);
    }

    // No result.code and isError is not true => genuine success
    let is_error = result
        .get("isError")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if !is_error {
        return Some(Outcome::Success);
    }

    // isError=true with no code: treat as Neutral (should not happen in practice)
    Some(Outcome::Neutral)
}

/// JSON-RPC request handler.
///
/// Accepts MCP JSON-RPC requests via POST and returns responses. Every
/// request is routed through the same daemon handler as stdio, so
/// initialize, ping, tools/list and tools/call (fetch, search, crawl)
/// all work identically on both transports. See the module docs for
/// the session and cancellation model.
async fn mcp_handler(State(state): State<HttpState>, headers: HeaderMap, body: Bytes) -> Response {
    // Origin and Host first: a browser page or a rebound name gets a
    // 403 before anything is parsed. Then the auth gate: applies to
    // /mcp only; /health stays open for probes.
    if let Err(why) = request_allowed(&headers, state.cors_enabled, &state.bound) {
        return rpc_error(StatusCode::FORBIDDEN, -32000, why);
    }
    if !authorized(&state, &headers) {
        return rpc_error(StatusCode::UNAUTHORIZED, -32000, "unauthorized");
    }

    // Parse before dispatch: malformed bodies get a JSON-RPC -32700
    // envelope instead of a bare transport-layer 400.
    let req: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return rpc_error(StatusCode::BAD_REQUEST, -32700, "Parse error"),
    };
    let line = req.to_string();
    let method = req.get("method").and_then(Value::as_str).unwrap_or("");
    let is_notification = req.get("id").is_none();
    let sid_header = headers
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    // Track in-flight requests
    state.in_flight.fetch_add(1, AtomicOrdering::SeqCst);

    // Ensure we always decrement on exit
    let _in_flight_guard = InFlightGuard {
        in_flight: Arc::clone(&state.in_flight),
    };

    // Cancellation notifications are handled inline : they must reach
    // the running tool NOW, not after a full dispatch round-trip.
    // Mirrors the stdio transport's inline handling.
    if is_notification && method == "notifications/cancelled" {
        let cancels = resolve_cancels(&state, sid_header.as_deref());
        if let Some(rid) = req.pointer("/params/requestId").and_then(cancel_key)
            && let Some(sender) = cancels
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&rid)
        {
            let _ = sender.send(true);
        }
        // 202 Accepted, not 204: the streamable-HTTP spec mandates 202
        // for notification-only POSTs.
        return StatusCode::ACCEPTED.into_response();
    }

    // Session resolution: header wins; unknown ids are expired per
    // streamable-HTTP convention. initialize without a header mints a
    // new session echoed back on the response. Each session carries
    // its own issue-#27 compat mode; session-less clients share the
    // default (env override still applies per call).
    let mut new_session: Option<String> = None;
    let (cancels, mode_cell) = match sid_header.as_deref() {
        Some(sid) if !sid.is_empty() => match state.sessions.session_handles(sid) {
            Some(h) => h,
            None => return rpc_error(StatusCode::NOT_FOUND, -32001, "session expired or unknown"),
        },
        _ => {
            if method == "initialize" {
                let sid = new_session_id();
                new_session = Some(sid.clone());
                state.sessions.registry_or_create(&sid)
            } else {
                state.default_handles()
            }
        }
    };

    // Progress notifications have no reader on a POST: a sink drains
    // them for the life of the call so the forwarder never blocks.
    let (progress_tx, progress_rx) = mpsc::channel::<String>(256);
    let _sink = spawn_progress_sink(progress_rx);
    let request_id = req.get("id").and_then(cancel_key);

    let outcome = tokio::time::timeout(
        state.timeout,
        handle(&state.daemon, &line, &cancels, &progress_tx, &mode_cell),
    )
    .await;

    let mut response = match outcome {
        Err(_) => {
            // Timed out: drop any registry entry so the id can be
            // reused without leaking a dead watch sender.
            if let Some(rid) = request_id
                && let Some(sender) = cancels
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .remove(&rid)
            {
                drop(sender);
            }
            rpc_error(
                StatusCode::GATEWAY_TIMEOUT,
                -32603,
                &format!("request timed out after {}s", state.timeout.as_secs()),
            )
        }
        Ok(Some(resp_line)) => {
            // Record wall_guard outcome if applicable
            if let Some((_, url)) = extract_web_fetch_info(&req)
                && let Some(outcome) = extract_outcome(&resp_line)
            {
                let should_burn = state.wall_guard.record_outcome(&url, outcome);
                if should_burn {
                    // Initiate drain + shutdown
                    let state_clone = state.clone();
                    let wall_guard = Arc::clone(&state.wall_guard);
                    tokio::spawn(async move {
                        // Get uptime and streak count for logging
                        let status = wall_guard.ready_status();
                        let deadline =
                            tokio::time::sleep(Duration::from_secs(wall_guard.grace_secs()));
                        tokio::pin!(deadline);
                        loop {
                            if state_clone.in_flight.load(AtomicOrdering::SeqCst) <= 1 {
                                break;
                            }
                            tokio::select! {
                                _ = &mut deadline => break,
                                _ = tokio::time::sleep(Duration::from_millis(100)) => {}
                            }
                        }
                        crate::diag!(
                            "[wall_guard] instance burned, initiating graceful shutdown (total_walls={})",
                            status.total_walls
                        );
                        wall_guard.shutdown_notifier().notify_one();
                    });
                }
            }

            let resp: Value = serde_json::from_str(&resp_line).unwrap_or_else(|_| {
                json!({
                    "jsonrpc": "2.0", "id": null,
                    "error": { "code": -32603, "message": "internal error" }
                })
            });
            Json(resp).into_response()
        }
        Ok(None) => {
            // Notification: no body, 202 Accepted per the streamable-HTTP
            // spec (204 would also be "no content", but the spec names
            // 202 for notification-only POSTs). The progress sink has
            // been reading since before the call, so nothing waits here.
            StatusCode::ACCEPTED.into_response()
        }
    };

    if let Some(sid) = new_session
        && let Ok(hv) = sid.parse()
    {
        response.headers_mut().insert("mcp-session-id", hv);
    }
    response
}

/// Resolve the cancellation registry for a cancellation notification.
/// Unknown session ids fall back to the shared default registry: a
/// notification cannot carry a JSON-RPC error, so it is absorbed.
fn resolve_cancels(state: &HttpState, sid: Option<&str>) -> CancelMap {
    match sid {
        Some(s) if !s.is_empty() => state
            .sessions
            .registry(s)
            .unwrap_or_else(|| state.default_handles().0),
        _ => state.default_handles().0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers_with_bearer(token: Option<&str>) -> HeaderMap {
        let mut h = HeaderMap::new();
        if let Some(t) = token {
            h.insert(
                AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {t}")).unwrap(),
            );
        }
        h
    }

    #[test]
    fn cors_without_auth_is_refused() {
        assert!(validate_http_config(true, false).is_err());
    }

    #[test]
    fn cors_with_auth_is_allowed() {
        assert!(validate_http_config(true, true).is_ok());
    }

    #[test]
    fn no_cors_is_always_allowed_regardless_of_auth() {
        assert!(validate_http_config(false, false).is_ok());
        assert!(validate_http_config(false, true).is_ok());
    }

    // Browser pages are the one client class the server never asked
    // for: with auth off (the default) a page in a local browser can
    // POST a JSON-RPC body as a "simple request" that no CORS
    // preflight stops, and with DNS rebinding it reads the answer.
    // Native clients send no Origin and pass; a loopback page passes;
    // CORS mode (auth required) admits any origin on purpose.
    #[test]
    fn a_browser_origin_is_refused_unless_loopback_or_cors_mode() {
        let bound = Bound::new("127.0.0.1", 8765);
        let with = |name: &'static str, v: &str| {
            let mut h = HeaderMap::new();
            h.insert(name, HeaderValue::from_str(v).unwrap());
            h
        };
        let none = HeaderMap::new();
        assert!(
            request_allowed(&none, false, &bound).is_ok(),
            "no Origin: a native client"
        );
        for origin in [
            "https://evil.example",
            "http://evil.example:8765",
            "null",
            "http://127.0.0.1.evil.example",
            "http://localhost.evil.example:8765",
        ] {
            assert!(
                request_allowed(&with("origin", origin), false, &bound).is_err(),
                "{origin} must be refused"
            );
            assert!(
                request_allowed(&with("origin", origin), true, &bound).is_ok(),
                "{origin} is admitted in CORS mode, which requires auth"
            );
        }
        for origin in [
            "http://localhost",
            "http://localhost:3000",
            "http://127.0.0.1:8765",
            "https://127.0.0.1",
            "http://[::1]:8765",
            "HTTP://LOCALHOST:8765",
        ] {
            assert!(
                request_allowed(&with("origin", origin), false, &bound).is_ok(),
                "{origin} is a loopback page"
            );
        }
    }

    // The Host header is what DNS rebinding forges: a page at
    // attacker.example resolving to 127.0.0.1 reaches the server
    // with `Host: attacker.example`. A server bound to loopback only
    // answers to loopback names on its own port.
    #[test]
    fn a_loopback_server_refuses_a_foreign_host_header() {
        let bound = Bound::new("127.0.0.1", 8765);
        let host = |v: &str| {
            let mut h = HeaderMap::new();
            h.insert("host", HeaderValue::from_str(v).unwrap());
            h
        };
        for ok in [
            "127.0.0.1:8765",
            "localhost:8765",
            "[::1]:8765",
            "LOCALHOST:8765",
            "127.0.0.1",
            "localhost",
        ] {
            assert!(request_allowed(&host(ok), false, &bound).is_ok(), "{ok}");
        }
        for bad in [
            "attacker.example",
            "attacker.example:8765",
            "127.0.0.1:9999",
            "127.0.0.1.attacker.example:8765",
            "",
        ] {
            assert!(
                request_allowed(&host(bad), false, &bound).is_err(),
                "{bad:?}"
            );
        }
        // Bound to every interface on purpose: the operator chose a
        // reachable server, and no single name is the right one.
        let wide = Bound::new("0.0.0.0", 8765);
        assert!(request_allowed(&host("attacker.example:8765"), false, &wide).is_ok());
        // A loopback Origin still cannot come with a foreign Host.
        let mut both = host("attacker.example:8765");
        both.insert("origin", HeaderValue::from_static("http://localhost:8765"));
        assert!(request_allowed(&both, false, &bound).is_err());
    }

    // A crawl with a progress token beats once every 2 s for up to
    // 600 s: past the channel's 256 slots the forwarder used to block
    // and the finished call timed out.
    #[tokio::test]
    async fn progress_is_drained_while_a_tool_runs() {
        let (tx, rx) = mpsc::channel::<String>(256);
        let sink = spawn_progress_sink(rx);
        let pushed = tokio::time::timeout(Duration::from_secs(2), async {
            for i in 0..1_000 {
                tx.send(format!("progress {i}")).await.unwrap();
            }
        })
        .await;
        assert!(
            pushed.is_ok(),
            "1 000 progress lines must not block the tool"
        );
        drop(tx);
        tokio::time::timeout(Duration::from_secs(2), sink)
            .await
            .expect("the sink ends with its sender")
            .unwrap();
    }

    #[test]
    fn token_ok_no_token_configured_allows_all() {
        assert!(token_ok(None, &HeaderMap::new()));
        assert!(token_ok(None, &headers_with_bearer(Some("anything"))));
        // The pure matcher treats Some as auth-on; configured_http_token is
        // the single boundary that maps an exact empty value to None.
        assert!(!token_ok(Some(""), &HeaderMap::new()));
    }

    #[test]
    fn legacy_token_is_compared_without_trimming() {
        let expected = crate::config::configured_http_token(" padded token ");
        assert!(token_ok(
            expected,
            &headers_with_bearer(Some(" padded token "))
        ));
        assert!(!token_ok(
            expected,
            &headers_with_bearer(Some("padded token"))
        ));
    }

    #[test]
    fn token_ok_requires_bearer_when_configured() {
        let expected = Some("s3cret-token");
        assert!(!token_ok(expected, &HeaderMap::new()));
        assert!(!token_ok(expected, &headers_with_bearer(Some("wrong"))));
        assert!(token_ok(
            expected,
            &headers_with_bearer(Some("s3cret-token"))
        ));
        // Non-Bearer schemes don't match.
        let mut h = HeaderMap::new();
        h.insert(
            AUTHORIZATION,
            HeaderValue::from_str("Basic czM6Y3JldA==").unwrap(),
        );
        assert!(!token_ok(expected, &h));
        // Length mismatch is rejected by the length check.
        assert!(!token_ok(
            expected,
            &headers_with_bearer(Some("s3cret-token "))
        ));
    }

    #[test]
    fn constant_time_eq_basics() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(constant_time_eq(b"", b""));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(!constant_time_eq(b"ab", b"abc"));
    }

    #[test]
    fn session_ids_are_base62_and_unique() {
        let ids: std::collections::HashSet<String> = (0..1000).map(|_| new_session_id()).collect();
        assert_eq!(ids.len(), 1000, "session ids must not repeat");
        for id in &ids {
            assert_eq!(id.len(), 16);
            assert!(id.bytes().all(|b| b.is_ascii_alphanumeric()));
        }
    }

    fn backdate(table: &SessionTable, id: &str, by: Duration) -> bool {
        // False when the host booted more recently than `by` (Instant
        // arithmetic would underflow); callers skip such assertions.
        let Some(old) = Instant::now().checked_sub(by) else {
            return false;
        };
        table
            .sessions
            .lock()
            .unwrap()
            .get_mut(id)
            .unwrap()
            .last_seen = old;
        true
    }

    fn table_with(ids: &[&str]) -> SessionTable {
        let table = SessionTable {
            sessions: Mutex::new(HashMap::new()),
        };
        for id in ids {
            table.registry_or_create(id);
        }
        table
    }

    #[test]
    fn registry_unknown_is_none_known_roundtrips() {
        let table = table_with(&["sess-1"]);
        assert!(table.registry("sess-1").is_some());
        assert!(table.registry("nope").is_none());
        // Same registry comes back on the second lookup.
        let a = table.registry("sess-1").unwrap();
        let b = table.registry("sess-1").unwrap();
        assert!(Arc::ptr_eq(&a, &b));
    }

    #[test]
    fn remove_reports_existence() {
        let table = table_with(&["sess-1"]);
        assert!(table.remove("sess-1"));
        assert!(!table.remove("sess-1"));
        assert!(table.registry("sess-1").is_none());
    }

    #[test]
    fn gc_drops_idle_sessions() {
        let table = table_with(&["old", "fresh"]);
        if !backdate(&table, "old", Duration::from_secs(2)) {
            return; // host booted <2s ago; underflow, skip
        }
        let mut sessions = table
            .sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        table.gc_locked_with(&mut sessions, Duration::from_secs(1));
        drop(sessions);
        assert!(table.registry("old").is_none(), "idle session must be GC'd");
        assert!(table.registry("fresh").is_some());
    }

    #[test]
    fn eviction_bounds_table_and_spares_default() {
        let table = table_with(&[""]);
        // Fill with one more than MAX_SESSIONS named sessions, oldest
        // first so eviction order is deterministic.
        for i in 0..=MAX_SESSIONS {
            table.registry_or_create(&format!("s{i:04}"));
        }
        // The oldest named entries were evicted as the table filled.
        let live = table
            .sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(
            live.len() <= MAX_SESSIONS,
            "table must stay bounded, has {}",
            live.len()
        );
        assert!(live.contains_key(""), "default registry is never evicted");
        assert!(!live.contains_key("s0000"), "oldest named entry evicted");
        assert!(live.contains_key(&format!("s{MAX_SESSIONS:04}")));
    }

    // ── Wall-guard extract_outcome tests ─────────────────────────────────────
    //
    // Real JSON-RPC response fixtures captured from the live production service.
    // The previous implementation looked for structuredContent.ok / .code; the
    // production server never emits structuredContent at the JSON-RPC envelope
    // level — it appears only inside result.*. These tests pin the correct
    // parsing path.

    /// Production FAILURE fixture: result.code = "network.dns"
    const FIXTURE_FAILURE_DNS: &str = r#"{"id":1,"jsonrpc":"2.0","result":{"code":"network.dns","content":[{"type":"text","text":"[meta]"}],"errorKind":"permanent","isError":false}}"#;
    /// Production SUCCESS fixture: no result.code, has _meta fetch-debug
    const FIXTURE_SUCCESS: &str = r#"{"id":1,"jsonrpc":"2.0","result":{"_meta":{"com.donsetch/fetch-debug":{"elapsed_ms":113,"raw":true,"status":200,"tier":"1"}},"content":[{"type":"text","text":"<html><body>content</body></html>"}]}}"#;
    /// Wall blocking: wall.challenge
    const FIXTURE_WALL_CHALLENGE: &str = r#"{"id":2,"jsonrpc":"2.0","result":{"code":"wall.challenge","content":[{"type":"text","text":"[meta]"}],"errorKind":"walled","isError":false}}"#;
    /// Wall blocking: wall.challenge_unsolved
    const FIXTURE_WALL_CHALLENGE_UNSOLVED: &str = r#"{"id":3,"jsonrpc":"2.0","result":{"code":"wall.challenge_unsolved","content":[{"type":"text","text":"[meta]"}],"errorKind":"walled","isError":false}}"#;
    /// Wall blocking: wall.blocked
    const FIXTURE_WALL_BLOCKED: &str = r#"{"id":4,"jsonrpc":"2.0","result":{"code":"wall.blocked","content":[{"type":"text","text":"[meta]"}],"errorKind":"walled","isError":false}}"#;
    /// Neutral: wall.paywall
    const FIXTURE_WALL_PAYWALL: &str = r#"{"id":5,"jsonrpc":"2.0","result":{"code":"wall.paywall","content":[{"type":"text","text":"[meta]"}],"errorKind":"walled","isError":false}}"#;
    /// Neutral: wall.captcha
    const FIXTURE_WALL_CAPTCHA: &str = r#"{"id":6,"jsonrpc":"2.0","result":{"code":"wall.captcha","content":[{"type":"text","text":"[meta]"}],"errorKind":"walled","isError":false}}"#;
    /// Neutral: wall.auth
    const FIXTURE_WALL_AUTH: &str = r#"{"id":7,"jsonrpc":"2.0","result":{"code":"wall.auth","content":[{"type":"text","text":"[meta]"}],"errorKind":"permanent","isError":false}}"#;
    /// JSON-RPC error envelope (no "result" key)
    const FIXTURE_JSONRPC_ERROR: &str =
        r#"{"id":8,"jsonrpc":"2.0","error":{"code":-32603,"message":"internal error"}}"#;

    #[test]
    fn extract_outcome_failure_dns_is_neutral() {
        assert_eq!(extract_outcome(FIXTURE_FAILURE_DNS), Some(Outcome::Neutral));
    }

    #[test]
    fn extract_outcome_success_fixture_is_success() {
        assert_eq!(extract_outcome(FIXTURE_SUCCESS), Some(Outcome::Success));
    }

    #[test]
    fn extract_outcome_wall_challenge_is_blocking() {
        assert_eq!(
            extract_outcome(FIXTURE_WALL_CHALLENGE),
            Some(Outcome::WallBlocking)
        );
    }

    #[test]
    fn extract_outcome_wall_challenge_unsolved_is_blocking() {
        assert_eq!(
            extract_outcome(FIXTURE_WALL_CHALLENGE_UNSOLVED),
            Some(Outcome::WallBlocking)
        );
    }

    #[test]
    fn extract_outcome_wall_blocked_is_blocking() {
        assert_eq!(
            extract_outcome(FIXTURE_WALL_BLOCKED),
            Some(Outcome::WallBlocking)
        );
    }

    #[test]
    fn extract_outcome_wall_paywall_is_neutral() {
        assert_eq!(
            extract_outcome(FIXTURE_WALL_PAYWALL),
            Some(Outcome::Neutral)
        );
    }

    #[test]
    fn extract_outcome_wall_captcha_is_neutral() {
        assert_eq!(
            extract_outcome(FIXTURE_WALL_CAPTCHA),
            Some(Outcome::Neutral)
        );
    }

    #[test]
    fn extract_outcome_wall_auth_is_neutral() {
        assert_eq!(extract_outcome(FIXTURE_WALL_AUTH), Some(Outcome::Neutral));
    }

    #[test]
    fn extract_outcome_jsonrpc_error_envelope_is_none() {
        assert_eq!(extract_outcome(FIXTURE_JSONRPC_ERROR), None);
    }

    #[test]
    fn extract_outcome_garbage_is_none() {
        assert_eq!(extract_outcome("not json"), None);
        assert_eq!(extract_outcome("{}"), None);
        assert_eq!(extract_outcome(r#"{"jsonrpc":"2.0"}"#), None);
    }

    // ── (a) N distinct-URL wall.challenge responses for listed host flip /ready ──

    #[test]
    fn wall_challenge_n_distinct_urls_latches_ready() {
        // Drives extract_outcome + record_outcome (the mcp_handler path) with
        // real fixture strings.  Three distinct-URL wall.challenge responses
        // must flip the guard to burned.
        let notify = Arc::new(tokio::sync::Notify::new());
        let config = crate::mcp::wall_guard::WallGuardConfig {
            evict_after_walls: Some(3),
            evict_hosts: ["tapology.com"].iter().map(|s| s.to_string()).collect(),
            evict_grace_secs: 30,
            evict_min_uptime_secs: 0,
        };
        let guard = crate::mcp::wall_guard::WallGuard::new(config, notify);

        let o1 = extract_outcome(FIXTURE_WALL_CHALLENGE).unwrap();
        assert_eq!(o1, Outcome::WallBlocking);
        assert!(!guard.record_outcome("https://tapology.com/page1", o1));
        assert!(!guard.is_burned());

        let o2 = extract_outcome(FIXTURE_WALL_CHALLENGE).unwrap();
        assert!(!guard.record_outcome("https://tapology.com/page2", o2));
        assert!(!guard.is_burned());

        let o3 = extract_outcome(FIXTURE_WALL_CHALLENGE).unwrap();
        let latched = guard.record_outcome("https://tapology.com/page3", o3);
        assert!(latched, "third distinct wall must latch");
        assert!(guard.is_burned(), "/ready must flip to 503 (burned)");
        // /health is unconditional; it never checks is_burned()
    }

    // ── (b) wall.paywall/captcha/auth x20 never flip /ready ──

    #[test]
    fn neutral_wall_codes_x20_never_latch_ready() {
        let notify = Arc::new(tokio::sync::Notify::new());
        let config = crate::mcp::wall_guard::WallGuardConfig {
            evict_after_walls: Some(1),
            evict_hosts: ["tapology.com"].iter().map(|s| s.to_string()).collect(),
            evict_grace_secs: 30,
            evict_min_uptime_secs: 0,
        };
        let guard = crate::mcp::wall_guard::WallGuard::new(config, notify);

        for (i, fixture) in [
            FIXTURE_WALL_PAYWALL,
            FIXTURE_WALL_CAPTCHA,
            FIXTURE_WALL_AUTH,
        ]
        .iter()
        .enumerate()
        {
            for j in 0..7 {
                let outcome = extract_outcome(fixture).unwrap();
                assert_eq!(outcome, Outcome::Neutral);
                let url = format!("https://tapology.com/page{}-{}", i, j);
                assert!(!guard.record_outcome(&url, outcome));
            }
        }
        assert!(
            !guard.is_burned(),
            "21 neutral outcomes must never flip /ready"
        );
    }

    // ── (c) tapology ok, other-host wall x10, tapology ok => not burned ──

    #[test]
    fn tapology_ok_other_host_walls_tapology_ok_not_burned() {
        let notify = Arc::new(tokio::sync::Notify::new());
        let config = crate::mcp::wall_guard::WallGuardConfig {
            evict_after_walls: Some(3),
            evict_hosts: ["tapology.com"].iter().map(|s| s.to_string()).collect(),
            evict_grace_secs: 30,
            evict_min_uptime_secs: 0,
        };
        let guard = crate::mcp::wall_guard::WallGuard::new(config, notify);

        let ok = extract_outcome(FIXTURE_SUCCESS).unwrap();
        guard.record_outcome("https://tapology.com/ok1", ok);

        let wall = extract_outcome(FIXTURE_WALL_CHALLENGE).unwrap();
        for i in 0..10 {
            guard.record_outcome(&format!("https://othersite.com/page{i}"), wall);
        }
        assert!(
            !guard.is_burned(),
            "other-host walls must not burn tapology"
        );

        guard.record_outcome("https://tapology.com/ok2", ok);
        assert!(!guard.is_burned());
    }

    // ── (d) tapology wall xN distinct => burned even with other-host successes ──

    #[test]
    fn tapology_wall_n_distinct_burned_even_with_other_host_successes() {
        let notify = Arc::new(tokio::sync::Notify::new());
        let config = crate::mcp::wall_guard::WallGuardConfig {
            evict_after_walls: Some(3),
            evict_hosts: ["tapology.com"].iter().map(|s| s.to_string()).collect(),
            evict_grace_secs: 30,
            evict_min_uptime_secs: 0,
        };
        let guard = crate::mcp::wall_guard::WallGuard::new(config, notify);

        let wall = extract_outcome(FIXTURE_WALL_CHALLENGE).unwrap();
        let ok = extract_outcome(FIXTURE_SUCCESS).unwrap();

        guard.record_outcome("https://tapology.com/page1", wall);
        guard.record_outcome("https://other.com/ok", ok);
        guard.record_outcome("https://tapology.com/page2", wall);
        guard.record_outcome("https://other.com/ok2", ok);
        assert!(!guard.is_burned());

        let latched = guard.record_outcome("https://tapology.com/page3", wall);
        assert!(
            latched,
            "third tapology wall must latch despite other-host successes"
        );
        assert!(guard.is_burned());
    }

    // ── (e) production SUCCESS shape resets the streak ──

    #[test]
    fn production_success_shape_resets_streak() {
        let notify = Arc::new(tokio::sync::Notify::new());
        let config = crate::mcp::wall_guard::WallGuardConfig {
            evict_after_walls: Some(3),
            evict_hosts: ["tapology.com"].iter().map(|s| s.to_string()).collect(),
            evict_grace_secs: 30,
            evict_min_uptime_secs: 0,
        };
        let guard = crate::mcp::wall_guard::WallGuard::new(config, notify);

        let wall = extract_outcome(FIXTURE_WALL_CHALLENGE).unwrap();
        let success = extract_outcome(FIXTURE_SUCCESS).unwrap();
        assert_eq!(success, Outcome::Success);

        guard.record_outcome("https://tapology.com/page1", wall);
        guard.record_outcome("https://tapology.com/page2", wall);
        assert!(!guard.is_burned());

        guard.record_outcome("https://tapology.com/ok", success);

        guard.record_outcome("https://tapology.com/page3", wall);
        guard.record_outcome("https://tapology.com/page4", wall);
        assert!(
            !guard.is_burned(),
            "streak was reset; 2 new walls not enough"
        );

        let latched = guard.record_outcome("https://tapology.com/page5", wall);
        assert!(latched, "third new wall after reset must latch");
        assert!(guard.is_burned());
    }

    // ── Shutdown drain: in-flight <= 1 check ──
    //
    // The drain loop in mcp_handler uses <= 1 because the triggering request
    // itself is still counted (InFlightGuard hasn't dropped yet).  With
    // in_flight = 1 the loop exits on first poll; with in_flight > 1 it
    // waits until requests finish (or the grace deadline expires).

    #[tokio::test]
    async fn shutdown_drain_resolves_when_in_flight_le_1() {
        let in_flight = Arc::new(AtomicI64::new(1));
        let notify = Arc::new(tokio::sync::Notify::new());
        let notify_clone = Arc::clone(&notify);
        let in_flight_clone = Arc::clone(&in_flight);

        tokio::spawn(async move {
            let deadline = tokio::time::sleep(Duration::from_secs(5));
            tokio::pin!(deadline);
            loop {
                if in_flight_clone.load(AtomicOrdering::SeqCst) <= 1 {
                    break;
                }
                tokio::select! {
                    _ = &mut deadline => break,
                    _ = tokio::time::sleep(Duration::from_millis(10)) => {}
                }
            }
            notify_clone.notify_one();
        });

        // in_flight == 1: loop exits immediately
        tokio::time::timeout(Duration::from_secs(2), notify.notified())
            .await
            .expect("shutdown notify must fire when in_flight <= 1");
    }

    #[tokio::test]
    async fn shutdown_drain_waits_for_in_flight_to_drop() {
        let in_flight = Arc::new(AtomicI64::new(3));
        let notify = Arc::new(tokio::sync::Notify::new());
        let notify_clone = Arc::clone(&notify);
        let in_flight_clone = Arc::clone(&in_flight);
        let in_flight_dec = Arc::clone(&in_flight);

        tokio::spawn(async move {
            let deadline = tokio::time::sleep(Duration::from_secs(5));
            tokio::pin!(deadline);
            loop {
                if in_flight_clone.load(AtomicOrdering::SeqCst) <= 1 {
                    break;
                }
                tokio::select! {
                    _ = &mut deadline => break,
                    _ = tokio::time::sleep(Duration::from_millis(10)) => {}
                }
            }
            notify_clone.notify_one();
        });

        let early = tokio::time::timeout(Duration::from_millis(50), notify.notified()).await;
        assert!(early.is_err(), "drain must not fire while in_flight > 1");

        in_flight_dec.fetch_sub(2, AtomicOrdering::SeqCst);

        tokio::time::timeout(Duration::from_secs(2), notify.notified())
            .await
            .expect("drain must fire once in_flight drops to 1");
    }

    // ── extract_web_fetch_info ──

    #[test]
    fn extract_web_fetch_info_parses_tools_call() {
        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "web_fetch",
                "arguments": {"url": "https://tapology.com/events/123"}
            }
        });
        let result = extract_web_fetch_info(&req);
        assert_eq!(
            result,
            Some((
                "web_fetch".to_string(),
                "https://tapology.com/events/123".to_string()
            ))
        );
    }

    #[test]
    fn extract_web_fetch_info_ignores_non_web_fetch() {
        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "web_search", "arguments": {"url": "https://tapology.com/"}}
        });
        assert_eq!(extract_web_fetch_info(&req), None);
    }

    #[test]
    fn extract_web_fetch_info_ignores_non_tools_call() {
        let req = serde_json::json!({"method": "initialize", "id": 1});
        assert_eq!(extract_web_fetch_info(&req), None);
    }

    // ── Min-uptime floor ──
    //
    // record_outcome returns early on a repeated same URL; after the floor
    // passes a latch only happens on the NEXT distinct wall.

    #[test]
    fn min_uptime_floor_prevents_latch_until_new_distinct_wall() {
        let notify = Arc::new(tokio::sync::Notify::new());
        let config = crate::mcp::wall_guard::WallGuardConfig {
            evict_after_walls: Some(2),
            evict_hosts: ["tapology.com"].iter().map(|s| s.to_string()).collect(),
            evict_grace_secs: 30,
            evict_min_uptime_secs: 999_999, // floor never passes in a test
        };
        let guard = crate::mcp::wall_guard::WallGuard::new(config, notify);

        // Streak reaches 2 but uptime floor not met => no latch
        assert!(!guard.record_outcome("https://tapology.com/page1", Outcome::WallBlocking));
        assert!(!guard.record_outcome("https://tapology.com/page2", Outcome::WallBlocking));
        assert!(!guard.is_burned(), "uptime floor prevents latch");

        // Same URL repeated => early return, no streak advance (already in set)
        assert!(!guard.record_outcome("https://tapology.com/page1", Outcome::WallBlocking));
        assert!(!guard.is_burned(), "same URL must not advance streak");

        // A third distinct URL increments the streak further but still no latch
        assert!(!guard.record_outcome("https://tapology.com/page3", Outcome::WallBlocking));
        assert!(
            !guard.is_burned(),
            "still above uptime floor; no latch possible"
        );
    }
}
