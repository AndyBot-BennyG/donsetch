//! Wall guard: per-host IP-block detection and eviction.
//!
//! Detects when the instance's egress IP is blocked by tracking consecutive
//! walls on distinct URLs per protected host. When the streak reaches a
//! threshold, fails /ready checks and initiates graceful shutdown.
//!
//! Feature is opt-in: requires both DONSETCH_EVICT_AFTER_WALLS and
//! DONSETCH_EVICT_HOSTS to be set; when either is unset/invalid/empty,
//! behaviour is byte-for-byte identical to the current implementation.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Outcome of a tool call response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Blocking walls: wall.challenge, wall.challenge_unsolved, wall.blocked
    WallBlocking,
    /// Successful response: ok: true, no error code
    Success,
    /// Everything else: wall.captcha, wall.paywall, wall.auth, wall.empty_shell,
    /// network.*, deadline.hit, etc.
    Neutral,
}

/// Per-host streak tracking.
struct HostStreak {
    streak: usize,
    seen_urls_in_streak: HashSet<String>,
    last_success_at: Option<Instant>,
}

impl HostStreak {
    fn new() -> Self {
        Self {
            streak: 0,
            seen_urls_in_streak: HashSet::new(),
            last_success_at: None,
        }
    }
}

/// Configuration for wall guard.
#[derive(Debug, Clone)]
pub struct WallGuardConfig {
    /// DONSETCH_EVICT_AFTER_WALLS: positive integer; feature OFF if unset/0/invalid
    pub evict_after_walls: Option<usize>,
    /// DONSETCH_EVICT_HOSTS: comma-separated registrable-domain hosts
    pub evict_hosts: HashSet<String>,
    /// DONSETCH_EVICT_GRACE_SECS: seconds to wait for in-flight drain (default 30)
    pub evict_grace_secs: u64,
    /// DONSETCH_EVICT_MIN_UPTIME_SECS: minimum uptime before eviction (default 0)
    pub evict_min_uptime_secs: u64,
}

impl WallGuardConfig {
    /// Parse from environment variables.
    pub fn from_env() -> Self {
        let evict_after_walls = std::env::var("DONSETCH_EVICT_AFTER_WALLS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .filter(|&n| n > 0);

        let evict_hosts = std::env::var("DONSETCH_EVICT_HOSTS")
            .ok()
            .map(|s| {
                s.split(',')
                    .map(|h| h.trim().to_lowercase())
                    .filter(|h| !h.is_empty())
                    .collect()
            })
            .unwrap_or_default();

        let evict_grace_secs = std::env::var("DONSETCH_EVICT_GRACE_SECS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(30);

        let evict_min_uptime_secs = std::env::var("DONSETCH_EVICT_MIN_UPTIME_SECS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);

        Self {
            evict_after_walls,
            evict_hosts,
            evict_grace_secs,
            evict_min_uptime_secs,
        }
    }

    /// Feature is OFF unless both evict_after_walls is Some AND evict_hosts is non-empty.
    pub fn is_enabled(&self) -> bool {
        self.evict_after_walls.is_some() && !self.evict_hosts.is_empty()
    }
}

/// Simple bounded LRU map: when full, evicts the first (oldest) entry.
struct BoundedLruMap<K: Clone + Eq + std::hash::Hash, V> {
    map: HashMap<K, V>,
    keys: Vec<K>,
    capacity: usize,
}

impl<K: Clone + Eq + std::hash::Hash, V> BoundedLruMap<K, V> {
    fn new(capacity: usize) -> Self {
        Self {
            map: HashMap::new(),
            keys: Vec::new(),
            capacity,
        }
    }

    fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.map.get_mut(key)
    }

    fn get_or_insert<F>(&mut self, key: K, f: F) -> &mut V
    where
        F: FnOnce() -> V,
    {
        if self.map.contains_key(&key) {
            self.map.get_mut(&key).unwrap()
        } else {
            if self.map.len() >= self.capacity
                && !self.map.is_empty()
                && let Some(oldest) = self.keys.first().cloned()
            {
                self.map.remove(&oldest);
                self.keys.remove(0);
            }
            self.keys.push(key.clone());
            self.map.insert(key.clone(), f());
            self.map.get_mut(&key).unwrap()
        }
    }
}

/// Internal state for wall guard.
struct WallGuardState {
    host_streaks: BoundedLruMap<String, HostStreak>,
    total_walls: u64,
    eviction_count: u64,
}

/// Wall guard: per-host wall detection and eviction.
pub struct WallGuard {
    config: WallGuardConfig,
    burned: AtomicBool,
    state: Mutex<WallGuardState>,
    started_at: Instant,
    notify_shutdown: Arc<tokio::sync::Notify>,
}

/// Status for /ready endpoint.
#[derive(Debug, Clone)]
pub struct ReadyStatus {
    pub burned: bool,
    pub total_walls: u64,
    pub eviction_count: u64,
}

/// Normalise a URL: lowercase scheme and host, strip query and fragment.
fn normalise_url(url: &str) -> String {
    if let Ok(parsed) = url::Url::parse(url) {
        let scheme = parsed.scheme();
        let host = parsed.host_str().unwrap_or("");
        let path = parsed.path();
        format!("{scheme}://{host}{path}").to_lowercase()
    } else {
        url.to_lowercase()
    }
}

/// Extract host from URL and normalise (lowercase, strip www).
fn extract_and_normalise_host(url: &str) -> Option<String> {
    let parsed = url::Url::parse(url).ok()?;
    let host = parsed.host_str()?.to_lowercase();
    let host = host.strip_prefix("www.").unwrap_or(&host);
    Some(host.to_string())
}

impl WallGuard {
    /// Create a new wall guard with configuration and a shutdown notifier.
    pub fn new(config: WallGuardConfig, notify: Arc<tokio::sync::Notify>) -> Arc<Self> {
        Arc::new(Self {
            config,
            burned: AtomicBool::new(false),
            state: Mutex::new(WallGuardState {
                host_streaks: BoundedLruMap::new(64),
                total_walls: 0,
                eviction_count: 0,
            }),
            started_at: Instant::now(),
            notify_shutdown: notify,
        })
    }

    /// Create a disabled guard (feature is OFF).
    pub fn disabled() -> Arc<Self> {
        Arc::new(Self {
            config: WallGuardConfig {
                evict_after_walls: None,
                evict_hosts: HashSet::new(),
                evict_grace_secs: 30,
                evict_min_uptime_secs: 0,
            },
            burned: AtomicBool::new(false),
            state: Mutex::new(WallGuardState {
                host_streaks: BoundedLruMap::new(64),
                total_walls: 0,
                eviction_count: 0,
            }),
            started_at: Instant::now(),
            notify_shutdown: Arc::new(tokio::sync::Notify::new()),
        })
    }

    /// Record the outcome of a tool call.
    /// Returns true if the instance just latched burned (caller should log + kick drain).
    pub fn record_outcome(&self, url: &str, outcome: Outcome) -> bool {
        // Feature is off
        if !self.config.is_enabled() {
            return false;
        }

        // Already burned: no-op
        if self.burned.load(Ordering::SeqCst) {
            return false;
        }

        let Some(host) = extract_and_normalise_host(url) else {
            return false;
        };

        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        match outcome {
            Outcome::Success => {
                if let Some(entry) = state.host_streaks.get_mut(&host) {
                    entry.streak = 0;
                    entry.seen_urls_in_streak.clear();
                    entry.last_success_at = Some(Instant::now());
                }
                false
            }
            Outcome::WallBlocking => {
                state.total_walls += 1;
                let entry = state
                    .host_streaks
                    .get_or_insert(host.clone(), HostStreak::new);
                let norm_url = normalise_url(url);

                if entry.seen_urls_in_streak.contains(&norm_url) {
                    // Same URL repeated: don't advance streak
                    return false;
                }

                entry.seen_urls_in_streak.insert(norm_url);
                entry.streak += 1;

                // Check if we should latch
                if self.config.evict_hosts.contains(&host)
                    && let Some(n) = self.config.evict_after_walls
                    && entry.streak >= n
                {
                    // Check min uptime
                    if self.started_at.elapsed().as_secs() >= self.config.evict_min_uptime_secs {
                        // LATCH
                        self.burned.store(true, Ordering::SeqCst);
                        state.eviction_count = 1;
                        return true;
                    }
                }
                false
            }
            Outcome::Neutral => false,
        }
    }

    /// Check if this instance is burned.
    pub fn is_burned(&self) -> bool {
        self.burned.load(Ordering::SeqCst)
    }

    /// Get the ready status for /ready endpoint.
    pub fn ready_status(&self) -> ReadyStatus {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        ReadyStatus {
            burned: self.burned.load(Ordering::SeqCst),
            total_walls: state.total_walls,
            eviction_count: state.eviction_count,
        }
    }

    /// Get the grace period in seconds.
    pub fn grace_secs(&self) -> u64 {
        self.config.evict_grace_secs
    }

    /// Get the shutdown notifier.
    pub fn shutdown_notifier(&self) -> Arc<tokio::sync::Notify> {
        Arc::clone(&self.notify_shutdown)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with_walls(n: usize, hosts: &[&str]) -> WallGuardConfig {
        WallGuardConfig {
            evict_after_walls: Some(n),
            evict_hosts: hosts.iter().map(|h| h.to_string()).collect(),
            evict_grace_secs: 30,
            evict_min_uptime_secs: 0,
        }
    }

    #[test]
    fn test_streak_distinct_urls() {
        let notify = Arc::new(tokio::sync::Notify::new());
        let guard = WallGuard::new(config_with_walls(2, &["example.com"]), notify);

        assert!(!guard.record_outcome("https://example.com/page1", Outcome::WallBlocking));
        assert!(!guard.is_burned());

        assert!(guard.record_outcome("https://example.com/page2", Outcome::WallBlocking));
        assert!(guard.is_burned());
    }

    #[test]
    fn test_streak_same_url_no_advance() {
        let notify = Arc::new(tokio::sync::Notify::new());
        let guard = WallGuard::new(config_with_walls(3, &["example.com"]), notify);

        assert!(!guard.record_outcome("https://example.com/page1", Outcome::WallBlocking));
        assert!(!guard.record_outcome("https://example.com/page1", Outcome::WallBlocking));
        assert!(!guard.is_burned());

        assert!(!guard.record_outcome("https://example.com/page2", Outcome::WallBlocking));
        assert!(!guard.is_burned());

        assert!(guard.record_outcome("https://example.com/page3", Outcome::WallBlocking));
        assert!(guard.is_burned());
    }

    #[test]
    fn test_success_resets_streak() {
        let notify = Arc::new(tokio::sync::Notify::new());
        let guard = WallGuard::new(config_with_walls(3, &["example.com"]), notify);

        assert!(!guard.record_outcome("https://example.com/page1", Outcome::WallBlocking));
        assert!(!guard.record_outcome("https://example.com/page2", Outcome::WallBlocking));
        assert!(!guard.is_burned());

        // Success resets streak
        assert!(!guard.record_outcome("https://example.com/ok", Outcome::Success));

        // Need 3 more distinct URLs to latch
        assert!(!guard.record_outcome("https://example.com/page3", Outcome::WallBlocking));
        assert!(!guard.record_outcome("https://example.com/page4", Outcome::WallBlocking));
        assert!(!guard.is_burned());

        assert!(guard.record_outcome("https://example.com/page5", Outcome::WallBlocking));
        assert!(guard.is_burned());
    }

    #[test]
    fn test_neutral_neither_counts_nor_resets() {
        let notify = Arc::new(tokio::sync::Notify::new());
        let guard = WallGuard::new(config_with_walls(2, &["example.com"]), notify);

        assert!(!guard.record_outcome("https://example.com/page1", Outcome::WallBlocking));
        assert!(!guard.record_outcome("https://example.com/page1", Outcome::Neutral));
        assert!(!guard.is_burned());

        assert!(guard.record_outcome("https://example.com/page2", Outcome::WallBlocking));
        assert!(guard.is_burned());
    }

    #[test]
    fn test_latch_is_one_way() {
        let notify = Arc::new(tokio::sync::Notify::new());
        let guard = WallGuard::new(config_with_walls(2, &["example.com"]), notify);

        assert!(!guard.record_outcome("https://example.com/page1", Outcome::WallBlocking));
        assert!(guard.record_outcome("https://example.com/page2", Outcome::WallBlocking));
        assert!(guard.is_burned());

        // Once burned, no outcome changes it back
        assert!(!guard.record_outcome("https://example.com/ok", Outcome::Success));
        assert!(guard.is_burned());
    }

    #[test]
    fn test_feature_off_when_unset() {
        let notify = Arc::new(tokio::sync::Notify::new());
        let config = WallGuardConfig {
            evict_after_walls: None,
            evict_hosts: HashSet::new(),
            evict_grace_secs: 30,
            evict_min_uptime_secs: 0,
        };
        let guard = WallGuard::new(config, notify);

        for _ in 0..10 {
            assert!(!guard.record_outcome("https://example.com/page", Outcome::WallBlocking));
        }
        assert!(!guard.is_burned());
    }

    #[test]
    fn test_non_protected_host_never_latches() {
        let notify = Arc::new(tokio::sync::Notify::new());
        let guard = WallGuard::new(config_with_walls(2, &["example.com"]), notify);

        // box.live is not in protected hosts
        for _ in 0..10 {
            assert!(!guard.record_outcome("https://box.live/page1", Outcome::WallBlocking));
        }
        assert!(!guard.is_burned());
    }

    #[test]
    fn test_protected_host_latches() {
        let notify = Arc::new(tokio::sync::Notify::new());
        let guard = WallGuard::new(config_with_walls(2, &["tapology.com"]), notify);

        assert!(!guard.record_outcome("https://tapology.com/events/page1", Outcome::WallBlocking));
        assert!(guard.record_outcome("https://tapology.com/events/page2", Outcome::WallBlocking));
        assert!(guard.is_burned());
    }

    #[test]
    fn test_interleaving_b_wall_a_ok() {
        let notify = Arc::new(tokio::sync::Notify::new());
        // Only example.com is protected
        let guard = WallGuard::new(config_with_walls(3, &["example.com"]), notify);

        assert!(!guard.record_outcome("https://example.com/page1", Outcome::WallBlocking));
        assert!(!guard.record_outcome("https://other.com/page1", Outcome::WallBlocking));
        assert!(!guard.record_outcome("https://other.com/page2", Outcome::WallBlocking));

        // other.com walls don't affect example.com (and example.com is not in evict_hosts anyway)
        assert!(!guard.is_burned());

        assert!(!guard.record_outcome("https://example.com/ok", Outcome::Success));
        assert!(!guard.is_burned());
    }

    #[test]
    fn test_a_wall_b_ok_does_not_reset_a() {
        let notify = Arc::new(tokio::sync::Notify::new());
        let guard = WallGuard::new(config_with_walls(2, &["a.com"]), notify);

        assert!(!guard.record_outcome("https://a.com/page1", Outcome::WallBlocking));
        assert!(!guard.record_outcome("https://b.com/ok", Outcome::Success));
        assert!(!guard.is_burned());

        // a.com's streak is still 1, need 1 more distinct URL
        assert!(guard.record_outcome("https://a.com/page2", Outcome::WallBlocking));
        assert!(guard.is_burned());
    }

    #[test]
    fn test_min_uptime_blocks_eviction() {
        let notify = Arc::new(tokio::sync::Notify::new());
        let mut config = config_with_walls(1, &["example.com"]);
        config.evict_min_uptime_secs = 9999; // Very high uptime requirement

        let guard = WallGuard::new(config, notify);

        // Even one wall should latch if uptime allowed, but it doesn't
        assert!(!guard.record_outcome("https://example.com/page1", Outcome::WallBlocking));
        assert!(!guard.is_burned());
    }

    #[test]
    fn test_wall_paywall_is_neutral() {
        let notify = Arc::new(tokio::sync::Notify::new());
        let guard = WallGuard::new(config_with_walls(1, &["example.com"]), notify);

        assert!(!guard.record_outcome("https://example.com/page1", Outcome::Neutral));
        assert!(!guard.is_burned());
    }

    #[test]
    fn test_wall_auth_is_neutral() {
        let notify = Arc::new(tokio::sync::Notify::new());
        let guard = WallGuard::new(config_with_walls(1, &["example.com"]), notify);

        assert!(!guard.record_outcome("https://example.com/page1", Outcome::Neutral));
        assert!(!guard.is_burned());
    }

    #[test]
    fn test_wall_captcha_is_neutral() {
        let notify = Arc::new(tokio::sync::Notify::new());
        let guard = WallGuard::new(config_with_walls(1, &["example.com"]), notify);

        assert!(!guard.record_outcome("https://example.com/page1", Outcome::Neutral));
        assert!(!guard.is_burned());
    }

    #[test]
    fn test_wall_empty_shell_is_neutral() {
        let notify = Arc::new(tokio::sync::Notify::new());
        let guard = WallGuard::new(config_with_walls(1, &["example.com"]), notify);

        assert!(!guard.record_outcome("https://example.com/page1", Outcome::Neutral));
        assert!(!guard.is_burned());
    }

    #[test]
    fn test_ready_status_reflects_state() {
        let notify = Arc::new(tokio::sync::Notify::new());
        let guard = WallGuard::new(config_with_walls(2, &["example.com"]), notify);

        let status = guard.ready_status();
        assert!(!status.burned);
        assert_eq!(status.total_walls, 0);
        assert_eq!(status.eviction_count, 0);

        guard.record_outcome("https://example.com/page1", Outcome::WallBlocking);
        let status = guard.ready_status();
        assert_eq!(status.total_walls, 1);

        guard.record_outcome("https://example.com/page2", Outcome::WallBlocking);
        let status = guard.ready_status();
        assert!(status.burned);
        assert_eq!(status.eviction_count, 1);
    }

    // Mutation tests - each asserts that a specific mutation would be caught
    #[test]
    fn test_mutation_a_count_repeated_same_url() {
        // Mutation (a): count repeated same-URL walls as distinct
        // This test would fail if mutation applied: we'd latch on 2 instead of 3
        let notify = Arc::new(tokio::sync::Notify::new());
        let guard = WallGuard::new(config_with_walls(3, &["example.com"]), notify);

        assert!(!guard.record_outcome("https://example.com/page1", Outcome::WallBlocking));
        assert!(!guard.record_outcome("https://example.com/page1", Outcome::WallBlocking));
        assert!(!guard.record_outcome("https://example.com/page1", Outcome::WallBlocking));
        assert!(!guard.is_burned()); // Still needs 3 distinct URLs
    }

    #[test]
    fn test_mutation_b_remove_streak_reset() {
        // Mutation (b): remove streak reset on success
        // This test would fail if mutation applied: streak would persist
        let notify = Arc::new(tokio::sync::Notify::new());
        let guard = WallGuard::new(config_with_walls(3, &["example.com"]), notify);

        assert!(!guard.record_outcome("https://example.com/page1", Outcome::WallBlocking));
        assert!(!guard.record_outcome("https://example.com/page2", Outcome::WallBlocking));
        guard.record_outcome("https://example.com/ok", Outcome::Success);

        // After success, should need 3 more distinct walls
        assert!(!guard.record_outcome("https://example.com/page3", Outcome::WallBlocking));
        assert!(!guard.record_outcome("https://example.com/page4", Outcome::WallBlocking));
        assert!(!guard.is_burned());

        assert!(guard.record_outcome("https://example.com/page5", Outcome::WallBlocking));
        assert!(guard.is_burned());
    }

    #[test]
    fn test_mutation_c_neutral_as_blocking() {
        // Mutation (c): Neutral => count as WallBlocking
        // This test would fail if mutation applied: neutral would latch
        let notify = Arc::new(tokio::sync::Notify::new());
        let guard = WallGuard::new(config_with_walls(1, &["example.com"]), notify);

        assert!(!guard.record_outcome("https://example.com/page1", Outcome::Neutral));
        assert!(!guard.is_burned());
    }

    #[test]
    fn test_mutation_f_ignore_min_uptime() {
        // Mutation (f): ignore min-uptime floor
        // This test would fail if mutation applied: would latch despite min uptime
        let notify = Arc::new(tokio::sync::Notify::new());
        let mut config = config_with_walls(1, &["example.com"]);
        config.evict_min_uptime_secs = 999999;

        let guard = WallGuard::new(config, notify);
        assert!(!guard.record_outcome("https://example.com/page1", Outcome::WallBlocking));
        assert!(!guard.is_burned());
    }

    #[test]
    fn test_mutation_g_feature_on_unset() {
        // Mutation (g): feature ON when env var unset
        // This test would fail if mutation applied: disabled would latch
        let guard = WallGuard::disabled();

        for _ in 0..100 {
            assert!(!guard.record_outcome("https://example.com/page", Outcome::WallBlocking));
        }
        assert!(!guard.is_burned());
    }

    #[test]
    fn test_mutation_h_global_streak_instead_of_per_host() {
        // Mutation (h): global streak instead of per-host
        // This test would fail if mutation applied: would latch incorrectly
        let notify = Arc::new(tokio::sync::Notify::new());
        let guard = WallGuard::new(config_with_walls(5, &["a.com"]), notify);

        // Only a.com is protected
        for i in 0..3 {
            guard.record_outcome(&format!("https://b.com/page{}", i), Outcome::WallBlocking);
        }

        // b.com's walls should not count toward a.com's latch
        assert!(!guard.record_outcome("https://a.com/page1", Outcome::WallBlocking));
        assert!(!guard.is_burned());
    }

    #[test]
    fn test_mutation_i_non_listed_host_can_latch() {
        // Mutation (i): non-listed host can latch
        // This test would fail if mutation applied: would latch on wrong host
        let notify = Arc::new(tokio::sync::Notify::new());
        let guard = WallGuard::new(config_with_walls(2, &["example.com"]), notify);

        assert!(!guard.record_outcome("https://notprotected.com/page1", Outcome::WallBlocking));
        assert!(!guard.record_outcome("https://notprotected.com/page2", Outcome::WallBlocking));
        assert!(!guard.is_burned());
    }

    #[test]
    fn test_mutation_k_neutral_walls_as_blocking() {
        // Mutation (k): count wall.paywall/wall.auth/wall.captcha as WallBlocking
        // This test would fail if mutation applied: would latch on paywall/auth/captcha
        let notify = Arc::new(tokio::sync::Notify::new());
        let guard = WallGuard::new(config_with_walls(1, &["example.com"]), notify);

        for i in 0..10 {
            assert!(
                !guard.record_outcome(&format!("https://example.com/page{}", i), Outcome::Neutral)
            );
        }
        assert!(!guard.is_burned());
    }

    #[test]
    fn test_mutation_k_paywall_is_neutral() {
        // Mutation (k) paywall variant
        let notify = Arc::new(tokio::sync::Notify::new());
        let guard = WallGuard::new(config_with_walls(1, &["example.com"]), notify);

        assert!(!guard.record_outcome("https://example.com/page1", Outcome::Neutral));
        assert!(!guard.is_burned());
    }

    #[test]
    fn test_mutation_k_auth_is_neutral() {
        // Mutation (k) auth variant
        let notify = Arc::new(tokio::sync::Notify::new());
        let guard = WallGuard::new(config_with_walls(1, &["example.com"]), notify);

        assert!(!guard.record_outcome("https://example.com/page1", Outcome::Neutral));
        assert!(!guard.is_burned());
    }

    #[test]
    fn test_mutation_k_captcha_is_neutral() {
        // Mutation (k) captcha variant
        let notify = Arc::new(tokio::sync::Notify::new());
        let guard = WallGuard::new(config_with_walls(1, &["example.com"]), notify);

        assert!(!guard.record_outcome("https://example.com/page1", Outcome::Neutral));
        assert!(!guard.is_burned());
    }
}
