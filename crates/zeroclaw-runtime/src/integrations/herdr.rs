//! Herdr integration — agent lifecycle reporting to the Herdr sidebar.
//!
//! This integration is purely environment-variable driven. There is no `[herdr]`
//! config section. Enable it by setting these env vars:
//!
//! - `HERDR_ENV=1` — must be set to activate the integration
//! - `HERDR_SOCKET_PATH` — path to the Herdr daemon's Unix socket
//! - `HERDR_PANE_ID` — the Herdr pane identifier
//!
//! Uses tokio for async UDS I/O with bounded timeouts. Messages are sent
//! fire-and-forget; flush synchronously waits for pending writes at shutdown.

use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::Weak;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;
use tokio::io::AsyncWriteExt;
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::time::timeout;

use zeroclaw_api::observability_traits::{ObserverMetric, SidecarObserver};

use crate::observability::{
    BroadcastHookGuard, Observer, ObserverEvent, set_scoped_broadcast_hook,
};

// I/O timeouts

/// Maximum time to wait for a UDS connect before giving up.
const CONNECT_TIMEOUT: Duration = Duration::from_millis(200);
/// Maximum time to wait for a UDS write before giving up.
const IO_TIMEOUT: Duration = Duration::from_millis(500);
/// Maximum time to wait for the writer task to drain all pending messages
/// at shutdown. Bounds the total teardown latency.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);
/// Maximum time `send_guaranteed` will wait for queue space before giving up.
/// Must be < SHUTDOWN_TIMEOUT so the caller can react to failure.
const SEND_GUARANTEED_TIMEOUT: Duration = Duration::from_secs(5);

/// Connect to a Unix domain socket with a timeout using tokio.
#[cfg(unix)]
async fn connect_with_timeout(path: &str) -> Result<UnixStream, std::io::Error> {
    timeout(CONNECT_TIMEOUT, UnixStream::connect(path))
        .await
        .unwrap_or(Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "herdr connect timed out",
        )))
}

/// Write a JSON-RPC notification to a connected UDS stream with bounded timeouts.
#[cfg(unix)]
async fn send_on_stream(stream: &mut UnixStream, payload: &str) -> Result<(), std::io::Error> {
    timeout(IO_TIMEOUT, async {
        stream.write_all(payload.as_bytes()).await?;
        stream.write_all(b"\n").await?;
        stream.flush().await
    })
    .await
    .unwrap_or(Err(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "herdr write timed out",
    )))
}

// Socket discovery

const SOURCE: &str = "herdr:zeroclaw";
const AGENT: &str = "zeroclaw";

/// Install the hook from already-resolved env values. Factored out of
/// [`try_install_herdr_sidecar`] so the gating logic can be tested without
/// touching the process environment (`std::env::set_var` is `unsafe` on
/// Rust >= 1.80 because it is not thread-safe with concurrent reads).
///
/// Constructs the `HerdrClient` + `HerdrObserver` and stores a weak
/// back-reference so [`SidecarObserver::attach`] can recover the `Arc`
/// for the broadcast hook. Does **not** install the hook or emit any
/// startup messages — `attach` does both so the sidecar can be
/// re-attached to a different turn without re-constructing the client.
fn install_hook_from_env(
    socket_path: String,
    pane_id: String,
    _agent_alias: &str,
) -> Option<Arc<HerdrObserver>> {
    // UDS is Unix-only; silently skip on other platforms.
    #[cfg(not(unix))]
    {
        let _ = (socket_path, pane_id);
        return None;
    }

    let client = HerdrClient::new(socket_path, pane_id);
    let observer = Arc::new(HerdrObserver::new(client, None));
    let _ = observer.self_weak.set(Arc::downgrade(&observer));
    Some(observer)
}

/// Try to install a Herdr sidecar for the interactive CLI agent path.
/// Returns `Some(Arc<dyn SidecarObserver>)` when the Herdr environment is
/// active (`HERDR_ENV=1`, `HERDR_SOCKET_PATH`, `HERDR_PANE_ID` all set) and
/// the caller is interactive; otherwise `None`.
///
/// The returned observer is **not yet attached** — the caller must invoke
/// [`SidecarObserver::attach`] with the owning turn id and agent alias so
/// the sidecar installs its broadcast hook and emits the initial idle +
/// metadata startup pair. Likewise the caller (or its `SidecarScope` drop
/// guard) must invoke [`SidecarObserver::detach`] at turn end so the
/// terminal `release_agent` notification is flushed before teardown.
///
/// `interactive` must be `true` for the sidecar to be returned. The Herdr
/// integration is advertised as CLI-interactive-only; daemon, cron, channel,
/// and subagent callers pass `interactive = false` and must not mutate the
/// pane's process-wide Herdr state, since their lifecycle and flush
/// assumptions differ from the CLI one-shot / REPL path.
pub fn try_install_herdr_sidecar(
    interactive: bool,
    agent_alias: &str,
) -> Option<Arc<dyn SidecarObserver>> {
    if !interactive {
        return None;
    }
    if std::env::var("HERDR_ENV").as_deref() != Ok("1") {
        return None;
    }
    let socket_path = std::env::var("HERDR_SOCKET_PATH").ok()?;
    let pane_id = std::env::var("HERDR_PANE_ID").ok()?;
    install_hook_from_env(socket_path, pane_id, agent_alias)
        .map(|obs| obs as Arc<dyn SidecarObserver>)
}

// HerdrClient

#[cfg(test)]
type SpyFn = Arc<dyn Fn(&str, &serde_json::Map<String, serde_json::Value>) + Send + Sync>;

/// Maximum number of pending messages in the writer queue. Bounded to prevent
/// unbounded accumulation under backpressure.
const WRITER_QUEUE_CAPACITY: usize = 64;

/// Drop guard that sets the drain-done flag on any drop. This covers
/// three exit paths: normal exit, panic unwind, and task cancellation.
/// The writer task also sets the flag explicitly before breaking its loop;
/// the redundant set is idempotent.
#[cfg(unix)]
struct DrainOnPanic<'a>(&'a AtomicBool);

#[cfg(unix)]
impl Drop for DrainOnPanic<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

/// Client that sends JSON-RPC notifications to the herdr daemon via tokio UDS.
/// The `send()` method serializes and fires off an async write — it never
/// blocks the caller. Call `shutdown_drain()` to wait until pending writes complete
/// (used at startup and shutdown for guaranteed delivery).
pub(crate) struct HerdrClient {
    pane_id: String,
    #[cfg(test)]
    spy: Option<SpyFn>,
    #[cfg(unix)]
    writer: Mutex<Option<mpsc::Sender<String>>>,
    #[cfg(unix)]
    shutdown_tx: Mutex<Option<oneshot::Sender<()>>>,
    /// Atomic flag set by the writer task when it has finished draining.
    /// Read by `shutdown_drain` in a yield-spin bounded by SHUTDOWN_TIMEOUT.
    #[cfg(unix)]
    drain_done: Arc<AtomicBool>,
    /// Writer task handle, retained so tests can `abort` it to exercise
    /// the drop-on-cancel path of `DrainOnPanic`.
    #[cfg(all(unix, test))]
    writer_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl HerdrClient {
    pub(crate) fn new(socket_path: String, pane_id: String) -> Self {
        #[cfg(unix)]
        {
            let (tx, mut rx) = mpsc::channel::<String>(WRITER_QUEUE_CAPACITY);
            let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
            // Atomic flag for drain completion signalling. Single writer
            // (the task), single reader (`shutdown_drain`); no mutex needed.
            let drain_done = Arc::new(AtomicBool::new(false));
            let drain_done_for_task = Arc::clone(&drain_done);
            let socket_path = socket_path.clone();
            let _writer_handle = zeroclaw_spawn::spawn!(async move {
                let _drain_guard = DrainOnPanic(&drain_done_for_task);
                loop {
                    tokio::select! {
                        biased;
                        _ = &mut shutdown_rx => {
                            // Shutdown signal received, drain remaining messages
                            while let Some(payload) = rx.recv().await {
                                let mut stream = match connect_with_timeout(&socket_path).await {
                                    Ok(s) => s,
                                    Err(_) => continue,
                                };
                                let _ = send_on_stream(&mut stream, &payload).await;
                            }
                            // Signal drain completion to the sync flush path.
                            drain_done_for_task.store(true, Ordering::Release);
                            break;
                        }
                        maybe_payload = rx.recv() => {
                            match maybe_payload {
                                Some(payload) => {
                                    let mut stream = match connect_with_timeout(&socket_path).await {
                                        Ok(s) => s,
                                        Err(_) => continue,
                                    };
                                    let _ = send_on_stream(&mut stream, &payload).await;
                                }
                                None => {
                                    // Channel closed without shutdown signal;
                                    // signal drain done and exit.
                                    drain_done_for_task.store(true, Ordering::Release);
                                    break;
                                }
                            }
                        }
                    }
                }
            });
            Self {
                pane_id,
                #[cfg(test)]
                spy: None,
                writer: Mutex::new(Some(tx)),
                shutdown_tx: Mutex::new(Some(shutdown_tx)),
                drain_done,
                #[cfg(all(unix, test))]
                writer_handle: Mutex::new(Some(_writer_handle)),
            }
        }
        #[cfg(not(unix))]
        {
            let _ = socket_path;
            Self {
                pane_id,
                #[cfg(test)]
                spy: None,
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn new_with_spy<F>(_socket_path: String, pane_id: String, spy: F) -> Self
    where
        F: Fn(&str, &serde_json::Map<String, serde_json::Value>) + Send + Sync + 'static,
    {
        Self {
            pane_id,
            spy: Some(Arc::new(spy)),
            #[cfg(unix)]
            writer: Mutex::new(None),
            #[cfg(unix)]
            shutdown_tx: Mutex::new(None),
            #[cfg(unix)]
            drain_done: Arc::new(AtomicBool::new(true)),
            #[cfg(all(unix, test))]
            writer_handle: Mutex::new(None),
        }
    }

    /// Abort the writer task. Test-only — exercises the drop-on-cancel
    /// path of `DrainOnPanic` to prove `shutdown_drain` does not wait
    /// the full 2s timeout for a writer that no longer exists.
    #[cfg(all(unix, test))]
    pub(crate) fn abort_writer_for_test(&self) {
        if let Some(handle) = self.writer_handle.lock().take() {
            handle.abort();
        }
    }

    /// Wait for the writer task to drain all pending messages and exit.
    ///
    /// Spins on `drain_done` with `thread::yield_now` so the writer task
    /// is not starved the way it would be under a blocking `recv_timeout`.
    /// The timeout bounds the total drain time.
    pub(crate) fn shutdown_drain(&self, timeout_dur: Duration) {
        #[cfg(unix)]
        {
            // Close the sender so no new messages can be queued
            self.writer.lock().take();

            // Signal the writer task to enter drain mode
            if let Some(shutdown_tx) = self.shutdown_tx.lock().take() {
                let _ = shutdown_tx.send(());
            }

            // Wait for drain completion via the atomic flag with bounded spin.
            let deadline = Instant::now() + timeout_dur;
            while !self.drain_done.load(Ordering::Acquire) {
                if Instant::now() >= deadline {
                    break;
                }
                std::thread::yield_now();
            }
        }
        #[cfg(not(unix))]
        {
            let _ = timeout_dur;
        }
    }

    fn next_seq(&self) -> u64 {
        static NEXT_SEQ: OnceLock<AtomicU64> = OnceLock::new();
        let counter = NEXT_SEQ.get_or_init(|| {
            let base = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_micros() as u64)
                .unwrap_or(1_000_000_000_000_000);
            AtomicU64::new(base)
        });
        counter.fetch_add(1, Ordering::Relaxed)
    }

    fn request_id(&self) -> String {
        format!("{SOURCE}:{}", self.next_seq())
    }

    /// Build the JSON-RPC payload string for `method` + `params`, including
    /// the invariant envelope (`pane_id`, `source`, `agent`, `seq`, `id`).
    /// Shared by [`send`] (hot, lossy) and [`send_guaranteed`] (cold, retrying).
    fn build_payload(
        &self,
        method: &str,
        params: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<String, std::io::Error> {
        let mut params_map = serde_json::Map::new();
        params_map.insert(
            "pane_id".into(),
            serde_json::Value::String(self.pane_id.clone()),
        );
        params_map.insert("source".into(), serde_json::Value::String(SOURCE.into()));
        params_map.insert("agent".into(), serde_json::Value::String(AGENT.into()));
        params_map.insert(
            "seq".into(),
            serde_json::Value::Number(self.next_seq().into()),
        );
        for (k, v) in params {
            params_map.insert(k.clone(), v.clone());
        }

        let payload = serde_json::json!({
            "id": self.request_id(),
            "method": method,
            "params": params_map,
        });

        serde_json::to_string(&payload).map_err(std::io::Error::other)
    }

    /// Fire-and-forget via `try_send`. Drops on queue full — caller never blocks.
    fn send(
        &self,
        method: &str,
        params: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<(), std::io::Error> {
        #[cfg(test)]
        if let Some(spy) = &self.spy {
            spy(method, params);
            return Ok(());
        }

        let payload_str = self.build_payload(method, params)?;

        #[cfg(unix)]
        if let Some(tx) = self.writer.lock().as_ref() {
            match tx.try_send(payload_str) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(_)) => {}
                Err(mpsc::error::TrySendError::Closed(_)) => {}
            }
        }

        Ok(())
    }

    /// Cold-path send used only from [`HerdrObserver::flush`] and
    /// [`HerdrObserver::transit_to`] for the terminal `idle` +
    /// `pane.release_agent` pair. Retries with `thread::yield_now` on queue
    /// full so the writer task can drain items. The wait is bounded by
    /// `SEND_GUARANTEED_TIMEOUT` (1s) so this never blocks the agent loop
    /// indefinitely. Returns an error if the deadline expires, allowing the
    /// caller to decide whether to commit state.
    fn send_guaranteed(
        &self,
        method: &str,
        params: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<(), std::io::Error> {
        #[cfg(test)]
        if let Some(spy) = &self.spy {
            spy(method, params);
            return Ok(());
        }

        let payload_str = self.build_payload(method, params)?;

        #[cfg(unix)]
        if let Some(tx) = self.writer.lock().as_ref() {
            let mut current = payload_str;
            let deadline = Instant::now() + SEND_GUARANTEED_TIMEOUT;
            loop {
                match tx.try_send(current) {
                    Ok(()) => return Ok(()),
                    Err(mpsc::error::TrySendError::Full(p)) => {
                        current = p;
                        if Instant::now() >= deadline {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::TimedOut,
                                "send_guaranteed timed out waiting for queue space",
                            ));
                        }
                        std::thread::yield_now();
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => return Ok(()),
                }
            }
        }

        Ok(())
    }

    fn report_state(&self, state: &str) {
        let mut params = serde_json::Map::new();
        params.insert("state".into(), serde_json::Value::String(state.into()));
        let _ = self.send("pane.report_agent", &params);
    }

    fn report_metadata(&self, display_agent: &str) {
        let mut params = serde_json::Map::new();
        params.insert(
            "display_agent".into(),
            serde_json::Value::String(display_agent.into()),
        );
        let _ = self.send("pane.report_metadata", &params);
    }
}

// HerdrState

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HerdrState {
    Idle,
    Working,
    Blocked,
    Released,
}

// HerdrObserver

/// Observer that reports agent lifecycle to the herdr daemon.
///
/// State machine: `Idle` → activity event → `Working` → `AgentEnd` → `Idle`.
///
/// Events are filtered by `owning_turn_id`: only events whose `turn_id`
/// matches the owning interactive run are forwarded to herdr. This isolates
/// nested non-interactive runs (subagents) from the parent's pane state.
/// Child agents pass `interactive = false` to `try_install_herdr_sidecar`,
/// which returns `None` and installs no hook; even if they did install one,
/// the `owning_turn_id` filter would prevent their events from reaching the
/// parent's observer.
///
/// Implements [`SidecarObserver`] so the agent loop can attach/detach the
/// sidecar at turn boundaries via a `SidecarScope` guard, rather than
/// relying on the implicit drop order of a `BroadcastHookGuard` plus a
/// separate `FlushGuard`.
pub struct HerdrObserver {
    state: Mutex<HerdrState>,
    client: HerdrClient,
    /// Owning turn identity for event filtering. Set by `attach`, cleared by
    /// `detach`. Wrapped in a `Mutex` so `attach`/`detach` can mutate it
    /// through a `&self` reference after construction.
    owning_turn_id: Mutex<Option<String>>,
    /// Broadcast hook guard, held for the lifetime of the attached turn.
    /// `Some` while attached; `None` when detached or never attached.
    hook: Mutex<Option<BroadcastHookGuard>>,
    /// Weak back-reference to ourselves, set once at construction so
    /// `attach` can upgrade to an `Arc` and register it as the broadcast
    /// hook without requiring the caller to hand back the same `Arc`.
    self_weak: OnceLock<Weak<HerdrObserver>>,
}

impl HerdrObserver {
    pub(crate) fn new(client: HerdrClient, owning_turn_id: Option<&str>) -> Self {
        Self {
            state: Mutex::new(HerdrState::Idle),
            client,
            owning_turn_id: Mutex::new(owning_turn_id.map(|s| s.to_owned())),
            hook: Mutex::new(None),
            self_weak: OnceLock::new(),
        }
    }

    /// Store a weak reference to ourselves so [`SidecarObserver::attach`]
    /// can recover an `Arc` for the broadcast hook. Test-only — production
    /// callers register the weak via [`try_install_herdr_sidecar`].
    #[cfg(test)]
    pub(crate) fn seed_self_weak(self: &Arc<Self>) {
        let _ = self.self_weak.set(Arc::downgrade(self));
    }
}

impl HerdrObserver {
    fn transit_to(&self, state: &mut HerdrState, target: HerdrState) {
        if *state == target {
            return;
        }

        // For the terminal Released state, send the pair BEFORE committing.
        // If send fails, we don't commit — the next event can retry.
        // This prevents the "commit-then-drop" race where a full queue
        // silently loses the terminal pair and the state gate suppresses retry.
        if target == HerdrState::Released {
            let mut p = serde_json::Map::new();
            p.insert("state".into(), serde_json::Value::String("idle".into()));
            let r1 = self.client.send_guaranteed("pane.report_agent", &p);
            let r2 = self
                .client
                .send_guaranteed("pane.release_agent", &serde_json::Map::new());
            if r1.is_err() || r2.is_err() {
                // Failed to enqueue terminal pair; don't commit state.
                // The next AgentEnd/flush can retry.
                return;
            }
        }

        *state = target;
        match target {
            HerdrState::Released => {
                // Terminal pair already sent above; nothing more to do here.
            }
            HerdrState::Working => self.client.report_state("working"),
            HerdrState::Idle => self.client.report_state("idle"),
            HerdrState::Blocked => self.client.report_state("blocked"),
        }
    }
}

impl Observer for HerdrObserver {
    fn record_event(&self, event: &ObserverEvent) {
        // Filter by owning turn_id. Events without turn_id (notably TurnComplete)
        // cannot be attributed, so when we own a turn we skip them entirely —
        // AgentEnd drives the terminal transition. Trades intermediate idle flash
        // for correctness under nesting.
        {
            let owning = self.owning_turn_id.lock();
            if let Some(owning) = owning.as_deref() {
                match event {
                    ObserverEvent::AgentStart { turn_id, .. }
                    | ObserverEvent::LlmRequest { turn_id, .. }
                    | ObserverEvent::LlmResponse { turn_id, .. }
                    | ObserverEvent::AgentEnd { turn_id, .. }
                    | ObserverEvent::ToolCallStart { turn_id, .. }
                    | ObserverEvent::ToolCall { turn_id, .. }
                    | ObserverEvent::HistoryTrimmed { turn_id, .. }
                    | ObserverEvent::AuthorizationRequested { turn_id, .. }
                    | ObserverEvent::AuthorizationResponded { turn_id, .. } => {
                        if turn_id.as_deref() != Some(owning) {
                            return;
                        }
                    }
                    ObserverEvent::TurnComplete { turn_id, .. }
                        if turn_id.as_deref() != Some(owning) =>
                    {
                        return;
                    }
                    _ => {}
                }
            }
        }
        let mut state = self.state.lock();
        match event {
            ObserverEvent::AgentStart { .. } => {
                self.transit_to(&mut state, HerdrState::Idle);
            }
            ObserverEvent::LlmRequest { .. } | ObserverEvent::ToolCallStart { .. } => {
                self.transit_to(&mut state, HerdrState::Working);
            }
            ObserverEvent::LlmResponse { .. } => {
                self.transit_to(&mut state, HerdrState::Working);
            }
            ObserverEvent::ToolCall { .. } => {
                self.transit_to(&mut state, HerdrState::Working);
            }
            ObserverEvent::TurnComplete { .. } => {
                self.transit_to(&mut state, HerdrState::Idle);
            }
            ObserverEvent::AgentEnd { .. } => {
                self.transit_to(&mut state, HerdrState::Released);
            }
            ObserverEvent::AuthorizationRequested { .. } => {
                self.transit_to(&mut state, HerdrState::Blocked);
            }
            ObserverEvent::AuthorizationResponded { granted, .. } => {
                if *granted {
                    self.transit_to(&mut state, HerdrState::Working);
                } else {
                    self.transit_to(&mut state, HerdrState::Idle);
                }
            }
            _ => {}
        }
    }

    fn record_metric(&self, _metric: &ObserverMetric) {}

    fn flush(&self) {
        {
            let mut state = self.state.lock();
            if *state != HerdrState::Released {
                // Use transit_to so the terminal pair is sent BEFORE state commit.
                // If send fails, state is not committed and we return early;
                // shutdown_drain will still run to wait for any in-flight messages.
                self.transit_to(&mut state, HerdrState::Released);
            }
        }
        self.client.shutdown_drain(SHUTDOWN_TIMEOUT);
    }

    fn name(&self) -> &str {
        "herdr"
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl SidecarObserver for HerdrObserver {
    fn attach(&self, turn_id: &str, agent_alias: &str) {
        // Idempotent: if hook already installed, this is a no-op.
        if self.hook.lock().is_some() {
            return;
        }

        // Set the owning turn before installing the hook so the first routed
        // event (an `AgentStart` from the agent loop) is not filtered out.
        {
            let mut owning = self.owning_turn_id.lock();
            *owning = Some(turn_id.to_string());
        }

        // Compute unique display name: agent alias + last 2 chars of pane_id.
        // Use char-aware slicing to handle multi-byte UTF-8 pane IDs safely.
        let display_name = {
            let chars: Vec<char> = self.client.pane_id.chars().collect();
            if chars.len() > 2 {
                let suffix: String = chars[chars.len() - 2..].iter().collect();
                format!("{agent_alias}-{suffix}")
            } else {
                agent_alias.to_string()
            }
        };

        // Emit the startup sequence so herdr shows the agent immediately:
        // metadata + initial idle state. Stale state from a prior session is
        // cleared by releasing first (best-effort, ignored on failure).
        let _ = self
            .client
            .send("pane.release_agent", &serde_json::Map::new());
        self.client.report_metadata(&display_name);
        self.client.report_state("idle");

        // Install the broadcast hook so this observer receives every event
        // routed through the primary observer's fan-out. Recover the `Arc`
        // from the weak reference set at construction time.
        if let Some(arc) = self.self_weak.get().and_then(|weak| weak.upgrade()) {
            let guard = set_scoped_broadcast_hook(arc);
            *self.hook.lock() = Some(guard);
        }
    }

    fn detach(&self) {
        // Idempotent: if hook was never installed (or already detached),
        // take() returns None and we no-op.
        let guard = self.hook.lock().take();
        if let Some(guard) = guard {
            // Flush the terminal pair (idle + release_agent) and drain pending
            // writes. flush() only emits the terminal pair when state != Released;
            // subsequent calls are a no-op.
            self.flush();
            // Drop the guard to uninstall the broadcast hook. We hold it
            // until after flush() so events emitted during flush are still
            // routed (though after flush no further events are expected).
            drop(guard);
            // Clear ownership so stale events cannot re-enter the state machine.
            *self.owning_turn_id.lock() = None;
        }
    }

    fn owns_turn(&self, turn_id: Option<&str>) -> bool {
        let owning = self.owning_turn_id.lock();
        match (owning.as_deref(), turn_id) {
            (Some(owned), Some(id)) => owned == id,
            (Some(_), None) => false,
            (None, _) => false,
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::time::{Duration, Instant};
    use tempfile::tempdir;
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio::net::UnixListener;

    /// A spy that captures all `pane.report_agent` / `pane.release_agent`
    /// calls instead of sending them over UDS.
    #[derive(Clone, Default)]
    pub(crate) struct HerdrSpy {
        calls: Arc<Mutex<Vec<HerdrSpyCall>>>,
    }

    #[derive(Debug, Clone)]
    pub(crate) struct HerdrSpyCall {
        pub method: String,
        pub params: serde_json::Value,
    }

    impl HerdrSpy {
        pub(crate) fn new() -> Self {
            Self::default()
        }

        pub(crate) fn into_inner(self) -> Arc<Mutex<Vec<HerdrSpyCall>>> {
            self.calls
        }
    }

    /// Build a `HerdrClient` with the spy instead of connecting to a real UDS socket.
    pub(crate) fn make_spy_reporter(spy: HerdrSpy) -> (HerdrClient, Arc<Mutex<Vec<HerdrSpyCall>>>) {
        let calls = spy.into_inner();
        let calls_clone = calls.clone();
        let client = HerdrClient::new_with_spy(
            "/tmp/test-herdr.sock".into(),
            "test-pane".into(),
            move |method, params| {
                calls_clone.lock().push(HerdrSpyCall {
                    method: method.to_string(),
                    params: serde_json::Value::Object(params.clone()),
                });
            },
        );
        (client, calls)
    }

    /// Startup path with stale socket must return quickly and handle
    /// non-ASCII pane IDs. `install_hook_from_env` creates a client, then
    /// `attach()` sends the startup sequence (release_agent + metadata +
    /// idle). With a stale socket, each connect attempt times out in 200ms.
    /// Using an emoji pane_id also exercises the char-aware display_name
    /// suffix extraction (would panic on byte indexing).
    #[tokio::test]
    async fn attach_with_stale_socket_returns_quickly_and_handles_utf8() {
        let start = std::time::Instant::now();
        let sidecar = install_hook_from_env(
            "/tmp/nonexistent-herdr-test-socket.sock".into(),
            "test-🦀".into(),
            "test-agent",
        )
        .expect("install_hook_from_env should succeed");
        sidecar.attach("turn-1", "test-agent");
        let elapsed = start.elapsed();

        assert!(
            elapsed < Duration::from_millis(500),
            "startup with unavailable herdr socket should return quickly, took {:?}",
            elapsed,
        );
        sidecar.detach();
    }

    /// `try_install_herdr_sidecar(interactive)` must return `None` for
    /// non-interactive callers (daemon, cron, channels, subagents)
    /// regardless of env state. The integration is advertised as
    /// CLI-interactive-only and must not mutate pane state from other paths.
    ///
    /// We avoid `std::env::set_var` here because it is `unsafe` on Rust >= 1.80
    /// (not thread-safe with concurrent reads). The `interactive` gate runs
    /// before any env access, so we can verify it without touching the
    /// environment.
    #[test]
    fn try_install_herdr_sidecar_skips_non_interactive() {
        // Non-interactive callers must never get a sidecar, even if env
        // vars were set by some other process. The gate short-circuits before
        // any env read.
        assert!(
            try_install_herdr_sidecar(false, "test-agent").is_none(),
            "try_install_herdr_sidecar(false) must return None without consulting env vars"
        );
    }

    /// `HerdrObserver::flush()` must emit the idle + release_agent
    /// notifications exactly once and transition to `Released`, matching the
    /// AgentEnd / run-teardown drain contract.
    #[tokio::test]
    async fn herdr_observer_flush_drains_release_messages() {
        let spy = HerdrSpy::new();
        let (client, calls) = make_spy_reporter(spy);
        let observer = HerdrObserver::new(client, None);

        // Simulate the agent reaching Working state first so flush has
        // something to release from.
        observer.record_event(&ObserverEvent::LlmRequest {
            model_provider: "test".into(),
            model: "test".into(),
            messages_count: 1,
            channel: None,
            agent_alias: None,
            parent_agent_alias: None,
            turn_id: None,
        });
        calls.lock().clear();

        observer.flush();

        let captured: Vec<HerdrSpyCall> = calls.lock().clone();
        let methods: Vec<&str> = captured.iter().map(|c| c.method.as_str()).collect();

        // The flush must emit exactly two messages: an idle state report
        // followed by a release_agent notification.
        assert_eq!(
            captured.len(),
            2,
            "flush must emit exactly idle + release_agent, got {:?}",
            methods
        );
        assert_eq!(
            captured[0].method, "pane.report_agent",
            "first flush message must be a state report, got {:?}",
            methods
        );
        assert_eq!(
            captured[0].params.get("state").and_then(|s| s.as_str()),
            Some("idle"),
            "first flush message must report idle state"
        );
        assert_eq!(
            captured[1].method, "pane.release_agent",
            "second flush message must be release_agent, got {:?}",
            methods
        );

        // Double-flush is a no-op — the observer is already Released.
        let count_after_first = calls.lock().len();
        observer.flush();
        assert_eq!(
            calls.lock().len(),
            count_after_first,
            "second flush must not emit duplicate release messages"
        );
    }

    /// `next_seq()` must return monotonically increasing values. The
    /// counter is seeded from wall clock on first use (process-wide) to
    /// provide restart resilience: a process restarted after herdr stores a
    /// prior seq will have a higher starting value, avoiding silent message
    /// rejection. Monotonicity within a process is the testable property.
    #[tokio::test]
    async fn next_seq_is_monotonic() {
        let client = HerdrClient::new(
            "/tmp/nonexistent-herdr-test-socket.sock".into(),
            "test-pane".into(),
        );

        let seq1 = client.next_seq();
        let seq2 = client.next_seq();
        let seq3 = client.next_seq();

        assert!(seq2 > seq1, "seq must be monotonic: {} <= {}", seq2, seq1);
        assert!(seq3 > seq2, "seq must be monotonic: {} <= {}", seq3, seq2);
    }

    /// Shutdown drain test: verify ordered receipt of `idle` then
    /// `pane.release_agent` before shutdown completes. Uses a real
    /// `UnixListener` to receive messages and confirm ordering.
    #[tokio::test]
    async fn herdr_shutdown_drain_ordered_receipt() {
        let dir = tempdir().unwrap();
        let sock_path = dir.path().join("herdr-test.sock");
        let sock_str = sock_path.to_str().unwrap().to_string();

        // Bind a listener before starting the client
        let listener = UnixListener::bind(&sock_path).unwrap();

        // Create client and send messages
        let client = HerdrClient::new(sock_str.clone(), "test-pane".into());
        client.report_state("idle");
        let _ = client.send("pane.release_agent", &serde_json::Map::new());

        // Flush (drains the writer task)
        client.shutdown_drain(SHUTDOWN_TIMEOUT);

        // Now accept and read messages from the listener
        let mut received = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline && received.len() < 2 {
            if let Ok(Ok((stream, _))) =
                tokio::time::timeout(Duration::from_millis(50), listener.accept()).await
            {
                let mut reader = BufReader::new(stream);
                let mut line = String::new();
                if reader.read_line(&mut line).await.is_ok()
                    && let Ok(val) = serde_json::from_str::<serde_json::Value>(&line)
                    && let Some(method) = val.get("method").and_then(|m| m.as_str())
                {
                    received.push(method.to_string());
                }
            }
        }

        // Verify ordered receipt: idle then release_agent
        assert_eq!(
            received.len(),
            2,
            "expected 2 messages, got {}: {:?}",
            received.len(),
            received
        );
        assert_eq!(received[0], "pane.report_agent");
        assert_eq!(received[1], "pane.release_agent");
    }

    /// Shutdown drain bounded wait test: a peer that accepts the
    /// connection but never reads must not block shutdown longer than
    /// the timeout. This creates a genuinely unresponsive peer (the
    /// kernel send buffer fills, then `send_on_stream`'s write blocks
    /// or times out). The 2s `SHUTDOWN_TIMEOUT` bound must be honored
    /// even though the writer task cannot drain to completion.
    #[tokio::test]
    async fn herdr_shutdown_drain_bounded_wait() {
        let dir = tempdir().unwrap();
        let sock_path = dir.path().join("herdr-test-slow.sock");
        let sock_str = sock_path.to_str().unwrap().to_string();

        let listener = UnixListener::bind(&sock_path).unwrap();

        // Accept exactly one connection in the background and hold it
        // open without reading. This forces the writer to either fill
        // the kernel send buffer (then `write_all` blocks) or hit the
        // IO_TIMEOUT. Either way, the writer cannot drain.
        let _accept_handle = zeroclaw_spawn::spawn!(async move {
            if let Ok((stream, _)) = listener.accept().await {
                // Hold the stream alive but never read. Drop happens on
                // task cancellation. We use a `let _` binding to keep
                // the stream alive while `pending` parks forever.
                let _stream = stream;
                std::future::pending::<()>().await;
            }
        });

        // Give the listener a moment to start accepting.
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Create client and queue messages.
        let client = HerdrClient::new(sock_str.clone(), "test-pane".into());
        // Fill enough messages that the queue saturates even if the
        // kernel buffer absorbs the first few.
        for i in 0..WRITER_QUEUE_CAPACITY {
            let mut params = serde_json::Map::new();
            params.insert(
                "state".into(),
                serde_json::Value::String(format!("filler-{}", i)),
            );
            let _ = client.send("pane.report_agent", &params);
        }
        client.report_state("idle");
        let _ = client.send("pane.release_agent", &serde_json::Map::new());

        // Flush should complete within timeout even with unresponsive peer.
        let start = Instant::now();
        client.shutdown_drain(SHUTDOWN_TIMEOUT);
        let elapsed = start.elapsed();

        // Must complete within SHUTDOWN_TIMEOUT (2s) + 1s slack for
        // connect timeouts (200ms) and IO timeouts (500ms) that the
        // writer still has to work through before the wait terminates.
        assert!(
            elapsed < Duration::from_secs(3),
            "shutdown drain must be bounded, took {:?}",
            elapsed
        );

        // Must not return prematurely — at least the SHUTDOWN_TIMEOUT
        // must elapse before the bounded wait gives up. (Otherwise the
        // drain would silently no-op.)
        assert!(
            elapsed >= Duration::from_millis(100),
            "shutdown drain returned suspiciously fast: {:?}",
            elapsed
        );
    }

    /// Nested run isolation test: parent interactive run + child subagent
    /// (interactive=false). Verifies child events don't reach parent's
    /// herdr hook, parent session unchanged, child AgentEnd doesn't
    /// release parent's pane.
    #[tokio::test]
    async fn herdr_nested_run_isolation() {
        use crate::observability::{clear_broadcast_hook, set_scoped_broadcast_hook};

        clear_broadcast_hook();

        // Parent installs hook with owning turn_id
        let parent_turn_id = "parent-turn-123";
        let spy_parent = HerdrSpy::new();
        let (client_parent, calls_parent) = make_spy_reporter(spy_parent);
        let parent_observer = Arc::new(HerdrObserver::new(client_parent, Some(parent_turn_id)));
        let _parent_guard = set_scoped_broadcast_hook(parent_observer.clone());

        // Simulate parent activity
        let parent_start = ObserverEvent::AgentStart {
            model_provider: "test".into(),
            model: "test".into(),
            channel: None,
            agent_alias: None,
            turn_id: Some(parent_turn_id.to_string()),
        };
        let parent_llm = ObserverEvent::LlmRequest {
            model_provider: "test".into(),
            model: "test".into(),
            messages_count: 1,
            channel: None,
            agent_alias: None,
            parent_agent_alias: None,
            turn_id: Some(parent_turn_id.to_string()),
        };
        let parent_end = ObserverEvent::AgentEnd {
            model_provider: "test".into(),
            model: "test".into(),
            duration: Duration::from_millis(100),
            tokens_used: None,
            cost_usd: None,
            channel: None,
            agent_alias: None,
            turn_id: Some(parent_turn_id.to_string()),
        };

        // Parent events should be processed
        parent_observer.record_event(&parent_start);
        parent_observer.record_event(&parent_llm);
        parent_observer.record_event(&parent_end);

        // Child (subagent) events with different turn_id should be filtered out
        let child_turn_id = "child-turn-456";
        let child_start = ObserverEvent::AgentStart {
            model_provider: "test".into(),
            model: "test".into(),
            channel: None,
            agent_alias: None,
            turn_id: Some(child_turn_id.to_string()),
        };
        let child_llm = ObserverEvent::LlmRequest {
            model_provider: "test".into(),
            model: "test".into(),
            messages_count: 1,
            channel: None,
            agent_alias: None,
            parent_agent_alias: None,
            turn_id: Some(child_turn_id.to_string()),
        };
        let child_end = ObserverEvent::AgentEnd {
            model_provider: "test".into(),
            model: "test".into(),
            duration: Duration::from_millis(100),
            tokens_used: None,
            cost_usd: None,
            channel: None,
            agent_alias: None,
            turn_id: Some(child_turn_id.to_string()),
        };

        // Child events should NOT be processed by parent observer
        parent_observer.record_event(&child_start);
        parent_observer.record_event(&child_llm);
        parent_observer.record_event(&child_end);

        // Child TurnComplete has a DIFFERENT turn_id — should be FILTERED.
        // This verifies the owning-turn filter works for TurnComplete.
        let child_turn_complete = ObserverEvent::TurnComplete {
            turn_id: Some(child_turn_id.to_string()),
        };
        parent_observer.record_event(&child_turn_complete);

        // Verify only parent events were captured (6 events: start, llm, end for parent)
        let captured: Vec<_> = calls_parent.lock().drain(..).collect();
        let state_methods: Vec<&str> = captured
            .iter()
            .filter(|c| c.method == "pane.report_agent")
            .filter_map(|c| c.params.get("state").and_then(|s| s.as_str()))
            .collect();

        // Parent: LlmRequest→Working, AgentEnd→Idle+Release (initial Idle is implicit)
        assert_eq!(
            state_methods,
            vec!["working", "idle"],
            "child events should be filtered out, got {:?}",
            state_methods
        );

        // Verify no release_agent from child (child's AgentEnd would have emitted it)
        let release_count = captured
            .iter()
            .filter(|c| c.method == "pane.release_agent")
            .count();
        assert_eq!(
            release_count, 1,
            "only parent AgentEnd should emit release_agent"
        );
    }

    /// Saturated-queue regression: when the writer queue is saturated by a
    /// slow peer, `send_guaranteed` (used by `flush()` for the terminal
    /// `idle` + `pane.release_agent` pair) must succeed without timing out.
    ///
    /// The receiver accepts connections but never reads. The writer opens
    /// a new connection per message, fills the kernel send buffer
    /// immediately, and `send_on_stream`'s `write_all` blocks until the
    /// 500ms IO_TIMEOUT fires. Each message therefore takes ~500ms even
    /// though it is "lost" — the connection is dropped right after the
    /// timeout. This saturates the 64-item mpsc queue.
    ///
    /// The test creates an observer, puts it in Working state, fills the
    /// queue via lossy `send()`, waits for the writer to begin draining
    /// against the stuck peer, then calls `flush()` (which goes through
    /// `transit_to` with the send-before-commit logic). It verifies that
    /// `send_guaranteed` succeeds within its timeout, proving the terminal
    /// pair survives saturation. Ordered receipt under normal conditions is
    /// covered by `herdr_shutdown_drain_ordered_receipt`.
    #[tokio::test]
    async fn flush_send_guaranteed_succeeds_under_backpressure() {
        let dir = tempdir().unwrap();
        let sock_path = dir.path().join("herdr-backpressure.sock");
        let sock_str = sock_path.to_str().unwrap().to_string();

        // Bind listener and accept-and-park a peer that holds the connection
        // open without reading. The writer's per-message connect succeeds;
        // the first write fills the kernel send buffer; subsequent writes
        // hit the 500ms IO_TIMEOUT, serializing each message behind ~500ms
        // of wait. This saturates the 64-item mpsc queue.
        let listener = UnixListener::bind(&sock_path).unwrap();
        let _peer = zeroclaw_spawn::spawn!(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let _stream = stream;
                std::future::pending::<()>().await;
            }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;

        let client = HerdrClient::new(sock_str.clone(), "test-pane".into());
        let observer = HerdrObserver::new(client, None);

        // Put observer in Working state first
        observer.record_event(&ObserverEvent::LlmRequest {
            model_provider: "test".into(),
            model: "test".into(),
            messages_count: 1,
            channel: None,
            agent_alias: None,
            parent_agent_alias: None,
            turn_id: None,
        });

        // Fill the queue to capacity with lossy sends.
        // Use the client directly to bypass observer filtering.
        let client_for_fill = HerdrClient::new(sock_str.clone(), "test-pane".into());
        for i in 0..WRITER_QUEUE_CAPACITY {
            let mut params = serde_json::Map::new();
            params.insert(
                "state".into(),
                serde_json::Value::String(format!("filler-{}", i)),
            );
            let _ = client_for_fill.send("pane.report_agent", &params);
        }

        // Give the writer a head start so it's mid-flush on a stuck peer.
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Now call flush() which goes through transit_to(Released) with the
        // send-before-commit logic. This is the actual code path used at
        // agent teardown. send_guaranteed must succeed (not time out) even
        // though the queue is saturated and the writer is slow.
        observer.flush();

        // If we reach here, send_guaranteed succeeded. The terminal pair
        // was enqueued and will be delivered once the writer drains.
        // (Ordered receipt under normal conditions is verified by
        // herdr_shutdown_drain_ordered_receipt.)

        // Cleanup.
        client_for_fill.abort_writer_for_test();
    }

    /// Table-driven matrix covering all TurnComplete filter combinations.
    ///
    /// Cases:
    /// - No owner + None turn_id: processed (already Idle → no-op, no call)
    /// - No owner + Some turn_id: processed → Working then Idle
    /// - Owning + matching turn_id: processed → Idle
    /// - Owning + different turn_id: FILTERED
    /// - Owning + None turn_id: FILTERED (the gap that was missing before)
    #[tokio::test]
    async fn turn_complete_filter_matrix() {
        // Helper to build an LlmRequest event for the given turn_id.
        fn llm_request(turn_id: Option<&str>) -> ObserverEvent {
            ObserverEvent::LlmRequest {
                model_provider: "test".into(),
                model: "test".into(),
                messages_count: 1,
                channel: None,
                agent_alias: None,
                parent_agent_alias: None,
                turn_id: turn_id.map(|s| s.to_string()),
            }
        }

        // Helper to build a TurnComplete event for the given turn_id.
        fn turn_complete(turn_id: Option<&str>) -> ObserverEvent {
            ObserverEvent::TurnComplete {
                turn_id: turn_id.map(|s| s.to_string()),
            }
        }

        // Helper to extract state transitions from captured calls.
        fn captured_states(calls: &Arc<Mutex<Vec<HerdrSpyCall>>>) -> Vec<String> {
            calls
                .lock()
                .iter()
                .filter(|c| c.method == "pane.report_agent")
                .filter_map(|c| {
                    c.params
                        .get("state")
                        .and_then(|s| s.as_str())
                        .map(str::to_string)
                })
                .collect()
        }

        // Case 1: No owner + None turn_id — Idle → Idle (no-op, no calls)
        {
            let spy = HerdrSpy::new();
            let (client, calls) = make_spy_reporter(spy);
            let observer = HerdrObserver::new(client, None);
            observer.record_event(&turn_complete(None));
            assert!(
                calls.lock().is_empty(),
                "no owner + None turn_id: should be no-op (already Idle)"
            );
        }

        // Case 2: No owner + Some turn_id — processed normally
        {
            let spy = HerdrSpy::new();
            let (client, calls) = make_spy_reporter(spy);
            let observer = HerdrObserver::new(client, None);
            // LlmRequest → Working, then TurnComplete → Idle
            observer.record_event(&llm_request(Some("t1")));
            observer.record_event(&turn_complete(Some("t1")));
            let states = captured_states(&calls);
            assert_eq!(
                states,
                vec!["working", "idle"],
                "no owner: TurnComplete should transition to idle"
            );
        }

        // Case 3: Owning + matching turn_id — processed → Idle
        {
            let spy = HerdrSpy::new();
            let (client, calls) = make_spy_reporter(spy);
            let observer = HerdrObserver::new(client, Some("own-turn"));
            observer.record_event(&llm_request(Some("own-turn")));
            calls.lock().clear();
            observer.record_event(&turn_complete(Some("own-turn")));
            let states = captured_states(&calls);
            assert_eq!(
                states,
                vec!["idle"],
                "owning + matching turn_id: should transition to idle"
            );
        }

        // Case 4: Owning + different turn_id — FILTERED
        {
            let spy = HerdrSpy::new();
            let (client, calls) = make_spy_reporter(spy);
            let observer = HerdrObserver::new(client, Some("own-turn"));
            observer.record_event(&llm_request(Some("own-turn")));
            calls.lock().clear();
            observer.record_event(&turn_complete(Some("other-turn")));
            let states = captured_states(&calls);
            assert!(
                states.is_empty(),
                "owning + different turn_id: TurnComplete must be filtered"
            );
        }

        // Case 5: Owning + None turn_id — FILTERED (the previously untested gap)
        {
            let spy = HerdrSpy::new();
            let (client, calls) = make_spy_reporter(spy);
            let observer = HerdrObserver::new(client, Some("own-turn"));
            observer.record_event(&llm_request(Some("own-turn")));
            calls.lock().clear();
            observer.record_event(&turn_complete(None));
            let states = captured_states(&calls);
            assert!(
                states.is_empty(),
                "owning + None turn_id: TurnComplete must be filtered (cannot attribute)"
            );
        }
    }

    /// `attach()` must emit the exact startup sequence: `release_agent` →
    /// `report_metadata` (with display_name = `{agent_alias}-{last2 pane_id}`) →
    /// `report_state("idle")`. Also verifies the display_name suffix is
    /// correct for a normal ASCII pane_id.
    #[tokio::test]
    async fn attach_emits_startup_sequence_with_correct_display_name() {
        let spy = HerdrSpy::new();
        let (client, calls) = make_spy_reporter(spy);
        let observer = Arc::new(HerdrObserver::new(client, None));
        observer.seed_self_weak();
        observer.attach("turn-1", "my-agent");

        let captured: Vec<_> = calls.lock().drain(..).collect();
        assert_eq!(
            captured.len(),
            3,
            "attach must emit exactly 3 messages: release, metadata, idle"
        );
        assert_eq!(captured[0].method, "pane.release_agent");
        assert_eq!(captured[1].method, "pane.report_metadata");
        // pane_id = "test-pane" → last 2 chars = "ne" → display_name = "my-agent-ne"
        assert_eq!(
            captured[1]
                .params
                .get("display_agent")
                .and_then(|s| s.as_str()),
            Some("my-agent-ne"),
            "display_name must be {{agent_alias}}-{{last2 pane_id}}"
        );
        assert_eq!(captured[2].method, "pane.report_agent");
        assert_eq!(
            captured[2].params.get("state").and_then(|s| s.as_str()),
            Some("idle")
        );
        observer.detach();
    }

    /// `attach()` must be idempotent: calling it twice with the same turn
    /// must not re-install the hook or emit duplicate startup messages.
    #[tokio::test]
    async fn attach_is_idempotent() {
        let spy = HerdrSpy::new();
        let (client, calls) = make_spy_reporter(spy);
        let observer = Arc::new(HerdrObserver::new(client, None));
        observer.seed_self_weak();
        observer.attach("turn-1", "test-agent");
        let first_count = calls.lock().len();
        observer.attach("turn-1", "test-agent");
        assert_eq!(
            calls.lock().len(),
            first_count,
            "second attach must not emit duplicate messages"
        );
        observer.detach();
    }

    /// `detach()` must be idempotent: calling it when not attached is a
    /// no-op, and calling it after a real detach is also a no-op.
    #[tokio::test]
    async fn detach_is_idempotent() {
        let spy = HerdrSpy::new();
        let (client, calls) = make_spy_reporter(spy);
        let observer = Arc::new(HerdrObserver::new(client, None));
        observer.seed_self_weak();

        // Detach when never attached — no-op.
        observer.detach();
        assert!(
            calls.lock().is_empty(),
            "detach when never attached must be a no-op"
        );

        // Attach then detach — emits terminal pair.
        observer.attach("turn-1", "test-agent");
        calls.lock().clear();
        observer.detach();
        let count_after_first = calls.lock().len();
        assert!(
            count_after_first > 0,
            "detach after attach must emit terminal messages"
        );

        // Second detach — no-op.
        observer.detach();
        assert_eq!(
            calls.lock().len(),
            count_after_first,
            "second detach must not emit duplicate messages"
        );
    }

    /// Re-attach after detach must transition to the new turn and filter
    /// events from the old turn. This is the core production path for REPL
    /// multi-turn support — the entire reason the SidecarObserver pattern
    /// exists.
    #[tokio::test]
    async fn reattach_after_detach_transitions_to_new_turn() {
        let spy = HerdrSpy::new();
        let (client, calls) = make_spy_reporter(spy);
        let observer = Arc::new(HerdrObserver::new(client, None));
        observer.seed_self_weak();

        // First turn — attach, emit an event, detach.
        observer.attach("turn-A", "test-agent");
        observer.record_event(&ObserverEvent::LlmRequest {
            model_provider: "test".into(),
            model: "test".into(),
            messages_count: 1,
            channel: None,
            agent_alias: None,
            parent_agent_alias: None,
            turn_id: Some("turn-A".to_string()),
        });
        observer.detach();
        calls.lock().clear();

        // Second turn — re-attach to turn-B.
        observer.attach("turn-B", "test-agent");
        // Clear startup emissions (release_agent + metadata + idle) before
        // checking the actual event-driven transitions.
        calls.lock().clear();

        // Events with turn-B must be processed.
        observer.record_event(&ObserverEvent::LlmRequest {
            model_provider: "test".into(),
            model: "test".into(),
            messages_count: 1,
            channel: None,
            agent_alias: None,
            parent_agent_alias: None,
            turn_id: Some("turn-B".to_string()),
        });
        let states: Vec<String> = calls
            .lock()
            .iter()
            .filter(|c| c.method == "pane.report_agent")
            .filter_map(|c| {
                c.params
                    .get("state")
                    .and_then(|s| s.as_str())
                    .map(str::to_string)
            })
            .collect();
        assert_eq!(
            states,
            vec!["working"],
            "turn-B events must be processed after re-attach"
        );

        // Events with the OLD turn-A must be filtered.
        calls.lock().clear();
        observer.record_event(&ObserverEvent::AgentEnd {
            model_provider: "test".into(),
            model: "test".into(),
            duration: Duration::from_millis(10),
            tokens_used: None,
            cost_usd: None,
            channel: None,
            agent_alias: None,
            turn_id: Some("turn-A".to_string()),
        });
        let states2: Vec<String> = calls
            .lock()
            .iter()
            .filter(|c| c.method == "pane.report_agent")
            .filter_map(|c| {
                c.params
                    .get("state")
                    .and_then(|s| s.as_str())
                    .map(str::to_string)
            })
            .collect();
        assert!(
            states2.is_empty(),
            "turn-A events must be filtered after re-attach to turn-B"
        );

        observer.detach();
    }

    /// When the writer task is forcibly cancelled (e.g. `abort`), the
    /// `DrainOnPanic` guard must set `drain_done` on drop so
    /// `shutdown_drain` returns immediately rather than waiting the
    /// full 2s timeout for a task that no longer exists.
    ///
    /// This is a real crash test: we `abort` the writer task and verify
    /// that `shutdown_drain` returns well within its bounded timeout.
    #[tokio::test]
    async fn shutdown_drain_does_not_hang_when_writer_crashes() {
        let dir = tempdir().unwrap();
        let sock_path = dir.path().join("herdr-crash.sock");
        let sock_str = sock_path.to_str().unwrap().to_string();

        let client = HerdrClient::new(sock_str.clone(), "test-pane".into());

        // Give the writer task a moment to spawn before we abort it.
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Forcefully cancel the writer task. This drops the
        // `DrainOnPanic` guard without panicking — the guard's `Drop`
        // impl must set `drain_done = true` so `shutdown_drain`
        // returns immediately.
        client.abort_writer_for_test();

        // Give the abort a moment to propagate.
        tokio::time::sleep(Duration::from_millis(50)).await;

        // shutdown_drain should return immediately — well under 1s —
        // because the writer's drop guard already set drain_done.
        let start = Instant::now();
        client.shutdown_drain(SHUTDOWN_TIMEOUT);
        let elapsed = start.elapsed();

        assert!(
            elapsed < Duration::from_secs(1),
            "shutdown_drain must return promptly after writer abort, took {:?}",
            elapsed
        );
    }
}
