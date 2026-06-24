use interprocess::local_socket::GenericFilePath;
#[cfg(windows)]
use interprocess::local_socket::GenericNamespaced;
use interprocess::local_socket::Stream;
use interprocess::local_socket::prelude::*;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex as StdMutex;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use zeroclaw_config::schema::HerdrConfig;
use crate::observability::{Observer, ObserverEvent};

const SOURCE: &str = "herdr:zeroclaw";
const AGENT: &str = "zeroclaw";

/// Debounced state reporter — coalesces rapid fire calls
pub struct DebouncedReporter {
    pub client: HerdrClient,
    pub last_report: Arc<Mutex<Option<(String, Instant)>>>,
    pub debounce_ms: u64,
}

impl DebouncedReporter {
    pub async fn report(&self, state: &str, session_id: Option<&str>) {
        let now = Instant::now();
        let mut guard = self.last_report.lock().await;

        if let Some((last_state, last_time)) = guard.as_ref()
            && last_state == state
            && now.duration_since(*last_time) < Duration::from_millis(self.debounce_ms)
        {
            return;
        }

        if let Err(e) = self.client.report_state(state, session_id).await {
            ::zeroclaw_log::record!(
                WARN,
                ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note)
                    .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                    .with_attrs(::serde_json::json!({"state": state, "error": format!("{:#}", e)})),
                "herdr report_state failed"
            );
        }
        *guard = Some((state.to_string(), now));
    }

    pub async fn report_session(&self, session_id: &str) -> anyhow::Result<()> {
        self.client.report_session(session_id).await
    }
}

pub struct HerdrClient {
    socket_path: PathBuf,
    pane_id: String,
    seq: AtomicU64,
}

impl HerdrClient {
    /// Create from config + env. Returns None if not configured.
    pub fn from_config(config: &HerdrConfig) -> Option<Self> {
        let socket_path = if !config.socket_path.is_empty() {
            eprintln!("[HERDR] from_config: using config.socket_path = {}", config.socket_path);
            PathBuf::from(&config.socket_path)
        } else {
            eprintln!("[HERDR] from_config: reading HERDR_SOCKET_PATH from env");
            match std::env::var("HERDR_SOCKET_PATH").ok() {
                Some(v) => {
                    eprintln!("[HERDR] from_config: HERDR_SOCKET_PATH = {}", v);
                    v.into()
                }
                None => {
                    eprintln!("[HERDR] from_config: HERDR_SOCKET_PATH NOT SET");
                    return None;
                }
            }
        };

        let pane_id = match std::env::var("HERDR_PANE_ID").ok() {
            Some(v) => {
                eprintln!("[HERDR] from_config: HERDR_PANE_ID = {}", v);
                v
            }
            None => {
                eprintln!("[HERDR] from_config: HERDR_PANE_ID NOT SET");
                return None;
            }
        };

        Some(Self {
            socket_path,
            pane_id,
            seq: AtomicU64::new(0),
        })
    }

    pub async fn report_state(&self, state: &str, session_id: Option<&str>) -> anyhow::Result<()> {
        let params = serde_json::json!({
            "pane_id": self.pane_id,
            "source": SOURCE,
            "agent": AGENT,
            "seq": self.seq.fetch_add(1, Ordering::Relaxed),
            "state": state,
            "agent_session_id": session_id,
        });
        self.send_request("pane.report_agent", params).await
    }

    pub async fn report_session(&self, session_id: &str) -> anyhow::Result<()> {
        let params = serde_json::json!({
            "pane_id": self.pane_id,
            "source": SOURCE,
            "agent": AGENT,
            "seq": self.seq.fetch_add(1, Ordering::Relaxed),
            "agent_session_id": session_id,
        });
        if let Err(e) = self.send_request("pane.report_agent_session", params).await {
            ::zeroclaw_log::record!(
                WARN,
                ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note)
                    .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                    .with_attrs(::serde_json::json!({"session_id": session_id, "error": format!("{:#}", e)})),
                "herdr report_session failed"
            );
        }
        Ok(())
    }

    fn connect(&self) -> std::io::Result<Stream> {
        #[cfg(unix)]
        {
            let name = self.socket_path.clone().to_fs_name::<GenericFilePath>()?;
            Stream::connect(name)
        }
        #[cfg(windows)]
        {
            let name = self.socket_path.to_string_lossy().to_string();
            let name = name.to_ns_name::<GenericNamespaced>()?;
            Stream::connect(name)
        }
    }

    async fn send_request(&self, method: &str, params: serde_json::Value) -> anyhow::Result<()> {
        let request = serde_json::json!({
            "id": format!("{}:{}:{:06}", SOURCE, chrono::Utc::now().timestamp_millis(), rand::random::<u32>() % 1_000_000),
            "method": method,
            "params": params,
        });

        let mut stream = match self.connect() {
            Ok(s) => s,
            Err(e) => {
                ::zeroclaw_log::record!(
                    WARN,
                    ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note)
                        .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                        .with_attrs(::serde_json::json!({"socket_path": self.socket_path.display().to_string(), "method": method, "error": format!("{:#}", e)})),
                    "herdr socket connect failed"
                );
                return Err(e.into());
            }
        };
        if let Err(e) = stream.write_all(request.to_string().as_bytes()) {
            ::zeroclaw_log::record!(
                WARN,
                ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note)
                    .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                    .with_attrs(::serde_json::json!({"method": method, "error": format!("{:#}", e)})),
                "herdr socket write failed"
            );
            return Err(e.into());
        }
        if let Err(e) = stream.write_all(b"\n") {
            ::zeroclaw_log::record!(
                WARN,
                ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note)
                    .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                    .with_attrs(::serde_json::json!({"method": method, "error": format!("{:#}", e)})),
                "herdr socket newline write failed"
            );
            return Err(e.into());
        }
        let _ = stream.flush();

        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf);
        Ok(())
    }
}

/// Observer for herdr integration — translates ObserverEvent into herdr state reports.
/// Installed via the broadcast hook in CLI paths.
pub struct HerdrObserver {
    reporter: Option<DebouncedReporter>,
    session_id: Arc<StdMutex<Option<String>>>,
}

impl HerdrObserver {
    /// Create a new HerdrObserver from config and optional session ID.
    pub fn new(config: &HerdrConfig, session_id: Option<String>) -> Self {
        let reporter = HerdrClient::from_config(config).map(|client| DebouncedReporter {
            client,
            last_report: Arc::new(Mutex::new(None::<(String, Instant)>)),
            debounce_ms: config.debounce_ms,
        });
        Self {
            reporter,
            session_id: Arc::new(StdMutex::new(session_id)),
        }
    }

    /// Set the session ID after construction (async version).
    pub async fn set_session_id(&self, id: String) {
        let mut guard = self.session_id.lock().await;
        *guard = Some(id);
    }

    /// Set the session ID after construction (sync version).
    pub fn set_session_id_sync(&self, id: Option<String>) {
        if let Ok(mut guard) = self.session_id.lock() {
            *guard = id;
        }
    }
}

impl Observer for HerdrObserver {
    fn record_event(&self, event: &ObserverEvent) {
        let Some(reporter) = &self.reporter else {
            return;
        };
        match event {
            ObserverEvent::AgentStart { .. } => {
                let session_id = self.session_id.lock().ok().and_then(|g| g.clone());
                if let Some(sid) = session_id.as_deref() {
                    let reporter = reporter.clone();
                    tokio::spawn(async move {
                        let _ = reporter.report_session(sid).await;
                    });
                }
                tokio::spawn({
                    let reporter = reporter.clone();
                    async move {
                        let _ = reporter.report("working", session_id.as_deref()).await;
                    }
                });
            }
            ObserverEvent::AgentEnd { .. } => {
                let session_id = self.session_id.lock().ok().and_then(|g| g.clone());
                tokio::spawn({
                    let reporter = reporter.clone();
                    async move {
                        let _ = reporter.report("idle", session_id.as_deref()).await;
                    }
                });
            }
            _ => {}
        }
    }

    fn record_metric(&self, _: &crate::observability::ObserverMetric) {}

    fn name(&self) -> &str {
        "herdr-observer"
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
