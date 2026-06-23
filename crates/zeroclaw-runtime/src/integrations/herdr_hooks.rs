use crate::hooks::{HookHandler, HookResult};
use crate::integrations::herdr::{DebouncedReporter, HerdrClient};
use zeroclaw_api::model_provider::{ChatMessage, ChatResponse};
use zeroclaw_api::tool::ToolResult;
use zeroclaw_config::schema::HerdrConfig;
use std::sync::Arc;
use std::time::Duration;
use serde_json::Value;

pub struct HerdrHook {
    reporter: Option<DebouncedReporter>,
    session_id: Arc<tokio::sync::Mutex<Option<String>>>,
    config: HerdrConfig,
}

impl HerdrHook {
    pub fn new(config: HerdrConfig) -> Self {
        let reporter = HerdrClient::from_config(&config).map(|client| DebouncedReporter {
            client,
            last_report: Arc::new(tokio::sync::Mutex::new(None)),
            debounce_ms: config.debounce_ms,
        });
        Self {
            reporter,
            session_id: Arc::new(tokio::sync::Mutex::new(None)),
            config,
        }
    }

    async fn report(&self, state: &str) {
        if let Some(reporter) = &self.reporter {
            let session_id = self.session_id.lock().await.clone();
            reporter.report(state, session_id.as_deref()).await;
        }
    }
}

#[async_trait::async_trait]
impl HookHandler for HerdrHook {
    fn name(&self) -> &str {
        "herdr-integration"
    }
    fn priority(&self) -> i32 {
        50
    }

    async fn on_session_start(&self, session_id: &str, _channel: &str) {
        *self.session_id.lock().await = Some(session_id.to_string());
        if let Some(reporter) = &self.reporter {
            let _ = reporter.report_session(session_id).await;
        }
        self.report("working").await;
    }

    async fn on_session_end(&self, _session_id: &str, _channel: &str) {
        self.report("idle").await;
        *self.session_id.lock().await = None;
    }

    async fn on_llm_input(&self, _messages: &[ChatMessage], _model: &str) {
        self.report("working").await;
    }

    async fn before_tool_call(&self, name: String, args: Value) -> HookResult<(String, Value)> {
        self.report("working").await;
        HookResult::Continue((name, args))
    }

    async fn on_llm_output(&self, _response: &ChatResponse) {
        self.report("idle").await;
    }

    async fn on_after_tool_call(&self, _tool: &str, _result: &ToolResult, _duration: Duration) {
        self.report("idle").await;
    }
}