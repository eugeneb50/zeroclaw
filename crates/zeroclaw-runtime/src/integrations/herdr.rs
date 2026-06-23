use interprocess::local_socket::prelude::*;
use interprocess::local_socket::Stream;
use interprocess::local_socket::GenericFilePath;
#[cfg(windows)]
use interprocess::local_socket::GenericNamespaced;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use zeroclaw_config::schema::HerdrConfig;

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

        if let Some((last_state, last_time)) = guard.as_ref() {
            if last_state == state && now.duration_since(*last_time) < Duration::from_millis(self.debounce_ms) {
                return;
            }
        }

        let _ = self.client.report_state(state, session_id).await;
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
            PathBuf::from(&config.socket_path)
        } else {
            std::env::var("HERDR_SOCKET_PATH").ok()?.into()
        };

        let pane_id = std::env::var("HERDR_PANE_ID").ok()?;

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
        self.send_request("pane.report_agent_session", params).await
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

        let mut stream = self.connect()?;
        stream.write_all(request.to_string().as_bytes())?;
        stream.write_all(b"\n")?;
        stream.flush()?;

        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf)?;
        Ok(())
    }
}