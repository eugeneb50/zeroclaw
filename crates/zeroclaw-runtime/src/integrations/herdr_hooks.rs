use crate::hooks::{HookHandler, HookResult};
use crate::integrations::herdr::{DebouncedReporter, HerdrClient};
use serde_json::Value;
use std::sync::Arc;
use std::time::Duration;
use zeroclaw_api::model_provider::{ChatMessage, ChatResponse};
use zeroclaw_api::tool::ToolResult;
use zeroclaw_config::schema::HerdrConfig;

pub struct HerdrHook {
    reporter: Option<DebouncedReporter>,
    session_id: Arc<tokio::sync::Mutex<Option<String>>>,
}

impl HerdrHook {
    pub fn new(config: &HerdrConfig) -> Self {
        eprintln!("[HERDR] HerdrHook::new called");
        let reporter = HerdrClient::from_config(config).map(|client| {
            eprintln!("[HERDR] HerdrClient created from config/env");
            DebouncedReporter {
                client,
                last_report: Arc::new(tokio::sync::Mutex::new(None)),
                debounce_ms: config.debounce_ms,
            }
        });
        eprintln!("[HERDR] reporter.is_some() = {}", reporter.is_some());
        Self {
            reporter,
            session_id: Arc::new(tokio::sync::Mutex::new(None)),
        }
    }

    async fn report(&self, state: &str) {
        eprintln!("[HERDR] report({}) called, reporter={}", state, self.reporter.is_some());
        if let Some(reporter) = &self.reporter {
            let session_id = self.session_id.lock().await.clone();
            eprintln!("[HERDR] report({}) -> sending, session_id={:?}", state, session_id);
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
        eprintln!("[HERDR] on_session_start({}, {})", session_id, _channel);
        *self.session_id.lock().await = Some(session_id.to_string());
        if let Some(reporter) = &self.reporter
            && let Err(e) = reporter.report_session(session_id).await
        {
            eprintln!("[HERDR] report_session failed: {:#}", e);
        }
        self.report("working").await;
    }

    async fn on_session_end(&self, _session_id: &str, _channel: &str) {
        eprintln!("[HERDR] on_session_end({})", _session_id);
        self.report("idle").await;
        *self.session_id.lock().await = None;
    }

    async fn on_llm_input(&self, _messages: &[ChatMessage], _model: &str) {
        eprintln!("[HERDR] on_llm_input");
        self.report("working").await;
    }

    async fn before_tool_call(&self, name: String, args: Value) -> HookResult<(String, Value)> {
        eprintln!("[HERDR] before_tool_call({})", name);
        self.report("working").await;
        HookResult::Continue((name, args))
    }

    async fn on_llm_output(&self, _response: &ChatResponse) {
        eprintln!("[HERDR] on_llm_output");
        self.report("idle").await;
    }

    async fn on_after_tool_call(&self, _tool: &str, _result: &ToolResult, _duration: Duration) {
        eprintln!("[HERDR] on_after_tool_call({})", _tool);
        self.report("idle").await;
    }
}
