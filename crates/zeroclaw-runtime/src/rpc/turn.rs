//! Shared turn execution. Single source of truth for spawn-drain-cancel.

use crate::agent::agent::{Agent, StreamedTurnError, StreamedTurnSuccess, TurnEvent};
use crate::agent::cost::{TOOL_LOOP_COST_TRACKING_CONTEXT, ToolLoopCostTrackingContext};
use crate::agent::loop_::is_tool_loop_cancelled;
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc};
use tokio_util::sync::CancellationToken;
use zeroclaw_api::model_provider::ConversationMessage;

pub enum TurnOutcome {
    Completed {
        text: String,
        messages: Vec<ConversationMessage>,
    },
    Cancelled {
        partial_text: String,
        messages: Vec<ConversationMessage>,
    },
}

#[derive(Debug)]
pub enum TurnError {
    Panicked(String),
    AgentError(String),
}

impl std::fmt::Display for TurnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Panicked(msg) => write!(f, "Turn task panicked: {msg}"),
            Self::AgentError(msg) => write!(f, "Agent turn failed: {msg}"),
        }
    }
}

impl std::error::Error for TurnError {}

/// Attribution fields attached to the tracing span for the duration of a turn.
/// All fields appear on every `record!()` emitted inside the turn.
#[derive(Clone, Default)]
pub struct TurnAttribution {
    pub session_key: Option<String>,
    pub agent_alias: String,
    pub model_provider: String,
    pub model: String,
    pub channel: &'static str,
}

pub async fn execute_turn<F, Fut>(
    agent: Arc<Mutex<Agent>>,
    prompt: String,
    cancel: CancellationToken,
    attribution: TurnAttribution,
    cost_context: Option<ToolLoopCostTrackingContext>,
    on_event: F,
) -> Result<TurnOutcome, TurnError>
where
    F: Fn(TurnEvent) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send,
{
    let (event_tx, mut event_rx) = mpsc::channel::<TurnEvent>(64);
    let cancel_clone = cancel.clone();
    let session_key = attribution.session_key.clone();

    let mut turn_handle = zeroclaw_spawn::spawn!(async move {
        let mut guard = agent.lock().await;
        let sk = attribution.session_key.clone();
        crate::agent::loop_::scope_session_key(attribution.session_key, async move {
            use ::zeroclaw_log::Instrument as _;
            let span = ::zeroclaw_log::info_span!(
                target: "zeroclaw_log_internal_scope",
                "zeroclaw_scope",
                session_key = %sk.as_deref().unwrap_or(""),
                agent_alias = %attribution.agent_alias,
                model_provider = %attribution.model_provider,
                model = %attribution.model,
                channel = %attribution.channel,
            );
            TOOL_LOOP_COST_TRACKING_CONTEXT
                .scope(
                    cost_context,
                    guard
                        .turn_streamed_with_steering_state(
                            &prompt,
                            event_tx,
                            Some(cancel_clone),
                            None,
                        )
                        .instrument(span),
                )
                .await
        })
        .await
    });

    let mut accumulated_text = String::new();

    let drain =
        drain_until_done_or_cancelled(&mut event_rx, &cancel, &mut accumulated_text, &on_event)
            .await;
    let _ = session_key; // consumed above

    match drain {
        DrainOutcome::Completed => {
            let joined = turn_handle
                .await
                .map_err(|e| TurnError::Panicked(format!("{e}")))?;
            outcome_from_task_result(joined, accumulated_text)
        }
        DrainOutcome::ExplicitCancel => {
            match tokio::time::timeout(CANCEL_GRACE, &mut turn_handle).await {
                Ok(joined) => outcome_from_task_result(
                    joined.map_err(|e| TurnError::Panicked(format!("cancelled turn join: {e}")))?,
                    accumulated_text,
                ),
                Err(_) => {
                    turn_handle.abort();
                    Ok(TurnOutcome::Cancelled {
                        partial_text: accumulated_text,
                        messages: Vec::new(),
                    })
                }
            }
        }
    }
}

/// Grace window allowing a cancelled turn task to commit its cooperative
/// unwind (synthesized tool results + `[interrupted]` message) into the agent
/// history before the dispatch path falls back to a hard abort.
const CANCEL_GRACE: std::time::Duration = std::time::Duration::from_secs(5);

/// Map a finished turn task into a [`TurnOutcome`]. A successful turn yields
/// `Completed`; a cooperative cancel yields `Cancelled` carrying the messages
/// the task committed so persistence never depends on the abort/commit race.
fn outcome_from_task_result(
    joined: Result<StreamedTurnSuccess, StreamedTurnError>,
    accumulated_text: String,
) -> Result<TurnOutcome, TurnError> {
    match joined {
        Ok(StreamedTurnSuccess {
            response,
            new_messages,
        }) => Ok(TurnOutcome::Completed {
            text: response,
            messages: new_messages,
        }),
        Err(StreamedTurnError {
            error,
            committed_response,
            new_messages,
        }) if is_tool_loop_cancelled(&error) => Ok(TurnOutcome::Cancelled {
            partial_text: if committed_response.is_empty() {
                accumulated_text
            } else {
                committed_response
            },
            messages: new_messages,
        }),
        Err(StreamedTurnError { error, .. }) => Err(TurnError::AgentError(format!("{error}"))),
    }
}

/// Why [`drain_until_done_or_cancelled`] returned. `ExplicitCancel` is an
/// outside fire (client RPC, reaper, session removal) that reached the drain.
/// There is no self-firing idle exit: a live turn falls silent for the whole
/// duration of a tool call, so silence is never treated as a stall.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DrainOutcome {
    Completed,
    ExplicitCancel,
}

async fn drain_until_done_or_cancelled<F, Fut>(
    event_rx: &mut mpsc::Receiver<TurnEvent>,
    cancel: &CancellationToken,
    accumulated: &mut String,
    on_event: &F,
) -> DrainOutcome
where
    F: Fn(TurnEvent) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    loop {
        if cancel.is_cancelled() {
            return DrainOutcome::ExplicitCancel;
        }
        tokio::select! {
            biased;
            _ = cancel.cancelled() => return DrainOutcome::ExplicitCancel,
            maybe_event = event_rx.recv() => {
                match maybe_event {
                    Some(event) => {
                        if let TurnEvent::Chunk { ref delta } = event {
                            accumulated.push_str(delta);
                        }
                        on_event(event).await;
                    }
                    None => return DrainOutcome::Completed,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    fn noop(_e: TurnEvent) -> std::future::Ready<()> {
        std::future::ready(())
    }

    #[tokio::test]
    async fn drain_must_not_idle_cancel_a_live_turn_across_a_long_tool_gap() {
        let (tx, mut rx) = mpsc::channel::<TurnEvent>(8);
        let cancel = CancellationToken::new();
        let mut acc = String::new();

        let sender = zeroclaw_spawn::spawn!(async move {
            let _ = tx
                .send(TurnEvent::ToolCall {
                    id: "c1".to_string(),
                    name: "shell".to_string(),
                    args: serde_json::json!({ "command": "cargo test" }),
                })
                .await;
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            let _ = tx
                .send(TurnEvent::ToolResult {
                    id: "c1".to_string(),
                    name: "shell".to_string(),
                    output: "ok".to_string(),
                })
                .await;
            let _ = tx
                .send(TurnEvent::Chunk {
                    delta: "done".to_string(),
                })
                .await;
        });

        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            drain_until_done_or_cancelled(&mut rx, &cancel, &mut acc, &noop),
        )
        .await
        .expect("drain must terminate when the live turn task completes");

        sender.await.unwrap();
        assert_eq!(
            outcome,
            DrainOutcome::Completed,
            "a turn whose sender is alive but quiet during a long tool \
             execution is NOT stalled; silence during execute_tools is the \
             normal case. Killing it is the idle_stall regression that froze \
             the TUI mid-turn (sessions 102, 103)."
        );
        assert!(
            !cancel.is_cancelled(),
            "drain self-cancelled a healthy turn across a tool gap; the token \
             must stay clean so downstream records no cancel."
        );
        assert_eq!(
            acc, "done",
            "drain dropped the post-tool chunk after wrongly tripping an idle \
             bound mid-execution."
        );
    }

    #[tokio::test]
    async fn drain_must_still_accumulate_chunks_when_events_arrive_steadily() {
        let (tx, mut rx) = mpsc::channel::<TurnEvent>(8);
        let cancel = CancellationToken::new();
        let mut acc = String::new();

        let sender = zeroclaw_spawn::spawn!(async move {
            for delta in ["he", "llo", " ", "world"] {
                let _ = tx
                    .send(TurnEvent::Chunk {
                        delta: delta.to_string(),
                    })
                    .await;
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            }
        });

        let cancelled = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            drain_until_done_or_cancelled(&mut rx, &cancel, &mut acc, &noop),
        )
        .await
        .expect("drain must terminate after the sender drops");

        sender.await.unwrap();
        assert_eq!(
            cancelled,
            DrainOutcome::Completed,
            "channel closure is not a cancel; drain returned the wrong verdict"
        );
        assert_eq!(
            acc, "hello world",
            "drain dropped chunks instead of accumulating them; a fix that \
             short-circuits with too-aggressive an idle window (e.g. <250ms) \
             would corrupt legitimate streaming turns. The production idle \
             window must sit comfortably between the inter-chunk gap of a \
             healthy stream (~hundreds of ms) and the user-perceptible hang \
             threshold (~seconds)."
        );
    }

    #[test]
    fn cancel_outcome_carries_committed_messages_not_just_partial_text() {
        let msgs = vec![ConversationMessage::Chat(
            zeroclaw_providers::ChatMessage::assistant("[interrupted by user]"),
        )];
        let err = StreamedTurnError {
            error: crate::agent::loop_::ToolLoopCancelled.into(),
            committed_response: "partial".to_string(),
            new_messages: msgs.clone(),
        };

        let outcome = outcome_from_task_result(Err(err), "accumulated".to_string())
            .expect("cooperative cancel maps to a Cancelled outcome, not an error");

        match outcome {
            TurnOutcome::Cancelled {
                partial_text,
                messages,
            } => {
                assert_eq!(
                    partial_text, "partial",
                    "committed_response from the task must win over the drain's \
                     accumulated text when present"
                );
                assert_eq!(
                    messages.len(),
                    msgs.len(),
                    "cancelled outcome dropped the messages the task committed"
                );
            }
            TurnOutcome::Completed { .. } => {
                panic!("a tool-loop cancel must not map to Completed")
            }
        }
    }

    #[test]
    fn non_cancel_agent_error_stays_an_error() {
        let err = StreamedTurnError {
            error: anyhow::Error::msg("provider exploded"),
            committed_response: String::new(),
            new_messages: Vec::new(),
        };
        let outcome = outcome_from_task_result(Err(err), String::new());
        assert!(
            matches!(outcome, Err(TurnError::AgentError(_))),
            "a genuine agent failure must surface as an error, not a silent \
             cancel"
        );
    }

    #[tokio::test]
    async fn execute_turn_scopes_cost_context_so_usage_is_persisted() {
        use crate::agent::agent::Agent;
        use crate::agent::dispatcher::NativeToolDispatcher;
        use crate::cost::CostTracker;
        use crate::observability::{NoopObserver, Observer};
        use async_trait::async_trait;
        use std::collections::HashMap;
        use zeroclaw_api::attribution::{Attributable, ModelProviderKind, ProviderKind, Role};
        use zeroclaw_api::model_provider::ModelProvider;
        use zeroclaw_memory::Memory;
        use zeroclaw_providers::ChatRequest;

        // Minimal provider that returns a final answer carrying non-zero token
        // usage on the non-streaming `chat` path (the default the engine takes
        // when the provider does not advertise streaming).
        struct UsageProvider;

        #[async_trait]
        impl ModelProvider for UsageProvider {
            async fn chat_with_system(
                &self,
                _system_prompt: Option<&str>,
                _message: &str,
                _model: &str,
                _temperature: Option<f64>,
            ) -> anyhow::Result<String> {
                Ok("ok".into())
            }

            async fn chat(
                &self,
                _request: ChatRequest<'_>,
                _model: &str,
                _temperature: Option<f64>,
            ) -> anyhow::Result<zeroclaw_providers::ChatResponse> {
                Ok(zeroclaw_providers::ChatResponse {
                    text: Some("done".into()),
                    tool_calls: vec![],
                    usage: Some(zeroclaw_providers::traits::TokenUsage {
                        input_tokens: Some(1_000),
                        cached_input_tokens: None,
                        output_tokens: Some(200),
                    }),
                    reasoning_content: None,
                })
            }
        }

        impl Attributable for UsageProvider {
            fn role(&self) -> Role {
                Role::Provider(ProviderKind::Model(ModelProviderKind::Custom))
            }
            fn alias(&self) -> &str {
                "mock-provider"
            }
        }

        let memory_cfg = zeroclaw_config::schema::MemoryConfig {
            backend: "none".into(),
            ..zeroclaw_config::schema::MemoryConfig::default()
        };
        let mem: Arc<dyn Memory> = Arc::from(
            zeroclaw_memory::create_memory(&memory_cfg, std::path::Path::new("/tmp"), None)
                .expect("memory creation should succeed"),
        );
        let workspace = tempfile::TempDir::new().expect("temp dir");
        let tracker = Arc::new(
            CostTracker::new(
                zeroclaw_config::schema::CostConfig {
                    enabled: true,
                    track_per_agent: true,
                    ..zeroclaw_config::schema::CostConfig::default()
                },
                workspace.path(),
            )
            .expect("cost tracker should initialize"),
        );
        let pricing = Arc::new(HashMap::from([(
            "mock-provider".to_string(),
            HashMap::from([
                ("test-model.input".to_string(), 3.0),
                ("test-model.output".to_string(), 15.0),
            ]),
        )]));
        let cost_context = ToolLoopCostTrackingContext::new(Arc::clone(&tracker), pricing)
            .with_agent_alias("rpc-agent");

        let agent = Agent::builder()
            .model_provider(Box::new(UsageProvider))
            .tools(vec![])
            .memory(mem)
            .observer(Arc::from(NoopObserver {}) as Arc<dyn Observer>)
            .tool_dispatcher(Box::new(NativeToolDispatcher))
            .workspace_dir(std::path::PathBuf::from("/tmp"))
            .model_name("test-model".into())
            .model_provider_name("mock-provider".into())
            .agent_alias("rpc-agent".into())
            .build()
            .expect("agent builder should succeed");

        let outcome = execute_turn(
            Arc::new(Mutex::new(agent)),
            "hello".to_string(),
            CancellationToken::new(),
            TurnAttribution {
                session_key: Some("s1".into()),
                agent_alias: "rpc-agent".into(),
                model_provider: "mock-provider".into(),
                model: "test-model".into(),
                channel: "rpc",
            },
            Some(cost_context),
            noop,
        )
        .await
        .expect("turn should complete");
        assert!(
            matches!(outcome, TurnOutcome::Completed { .. }),
            "turn should complete normally"
        );

        let summary = tracker.get_summary().expect("cost summary");
        assert_eq!(
            summary.request_count, 1,
            "execute_turn must scope the cost context so the turn's usage is \
             persisted (#5221)"
        );
        assert_eq!(summary.total_tokens, 1_200);
        let agent_summary = tracker
            .get_summary_for_agent("rpc-agent")
            .expect("agent-scoped summary");
        assert_eq!(
            agent_summary.request_count, 1,
            "the agent alias must flow through to the persisted cost record"
        );
    }

    /// Regression: the drain callback must resolve `model_context_window`
    /// from the embedded `provider_ref` via config, not by reacquiring the
    /// agent mutex. `execute_turn` holds `agent.lock()` for the whole turn;
    /// if the callback tried to lock the agent again the drain would stall
    /// after the first Usage event.
    ///
    /// This test drives the **real `execute_turn` RPC boundary** — the same
    /// function production dispatch calls — with a Usage-producing provider
    /// and a callback that reads config + resolves the window. It proves
    /// both the Usage and Chunk notifications complete while `execute_turn`
    /// owns the agent lock, and the callback resolves the correct context
    /// window from config without deadlock.
    #[tokio::test]
    async fn execute_turn_drain_callback_resolves_window_without_relocking_agent() {
        use crate::agent::agent::Agent;
        use crate::agent::dispatcher::NativeToolDispatcher;
        use crate::observability::{NoopObserver, Observer};
        use async_trait::async_trait;
        use std::sync::Arc;
        use std::sync::Mutex as StdMutex;
        use tokio::sync::Mutex;
        use zeroclaw_api::attribution::{Attributable, ModelProviderKind, ProviderKind, Role};
        use zeroclaw_api::model_provider::ModelProvider;
        use zeroclaw_config::schema::Config;
        use zeroclaw_memory::Memory;
        use zeroclaw_providers::ChatRequest;

        // Minimal provider that returns usage on the chat path.
        struct UsageProvider;

        #[async_trait]
        impl ModelProvider for UsageProvider {
            async fn chat_with_system(
                &self,
                _system: Option<&str>,
                _message: &str,
                _model: &str,
                _temperature: Option<f64>,
            ) -> anyhow::Result<String> {
                Ok("ok".into())
            }

            async fn chat(
                &self,
                _request: ChatRequest<'_>,
                _model: &str,
                _temperature: Option<f64>,
            ) -> anyhow::Result<zeroclaw_providers::ChatResponse> {
                Ok(zeroclaw_providers::ChatResponse {
                    text: Some("hello world".into()),
                    tool_calls: vec![],
                    usage: Some(zeroclaw_providers::traits::TokenUsage {
                        input_tokens: Some(500),
                        cached_input_tokens: None,
                        output_tokens: Some(100),
                    }),
                    reasoning_content: None,
                })
            }
        }

        impl Attributable for UsageProvider {
            fn role(&self) -> Role {
                Role::Provider(ProviderKind::Model(ModelProviderKind::Custom))
            }
            fn alias(&self) -> &str {
                "openai.default"
            }
        }

        // Build a config with a provider that has context_window set.
        let mut config = Config::default();
        config
            .providers
            .models
            .ensure("openai", "default")
            .expect("ensure provider")
            .context_window = Some(128_000);
        let config: Arc<parking_lot::RwLock<Config>> = Arc::new(config.into());

        let memory_cfg = zeroclaw_config::schema::MemoryConfig {
            backend: "none".into(),
            ..zeroclaw_config::schema::MemoryConfig::default()
        };
        let mem: Arc<dyn Memory> = Arc::from(
            zeroclaw_memory::create_memory(&memory_cfg, std::path::Path::new("/tmp"), None)
                .expect("memory creation should succeed"),
        );

        let agent = Agent::builder()
            .model_provider(Box::new(UsageProvider))
            .tools(vec![])
            .memory(mem)
            .observer(Arc::from(NoopObserver {}) as Arc<dyn Observer>)
            .tool_dispatcher(Box::new(NativeToolDispatcher))
            .workspace_dir(std::path::PathBuf::from("/tmp"))
            .model_name("test-model".into())
            .model_provider_name("openai.default".into())
            .agent_alias("rpc-agent".into())
            .build()
            .expect("agent builder should succeed");

        // Collect notification-type info from the drain callback.
        let usage_count = Arc::new(StdMutex::new(0usize));
        let chunk_count = Arc::new(StdMutex::new(0usize));
        let resolved_window = Arc::new(StdMutex::new(None::<u64>));

        let cfg_for_cb = Arc::clone(&config);
        let uc = Arc::clone(&usage_count);
        let cc = Arc::clone(&chunk_count);
        let rw = Arc::clone(&resolved_window);

        let outcome = execute_turn(
            Arc::new(Mutex::new(agent)),
            "hello".to_string(),
            CancellationToken::new(),
            TurnAttribution {
                session_key: Some("drain-test".into()),
                agent_alias: "rpc-agent".into(),
                model_provider: "openai.default".into(),
                model: "test-model".into(),
                channel: "rpc",
            },
            None,
            move |event| {
                let cfg = Arc::clone(&cfg_for_cb);
                let uc = Arc::clone(&uc);
                let cc = Arc::clone(&cc);
                let rw = Arc::clone(&rw);
                async move {
                    match &event {
                        TurnEvent::Usage { provider_ref, .. } => {
                            *uc.lock().unwrap() += 1;
                            // Resolve model_context_window from the embedded
                            // provider_ref via config.read() — NOT via the
                            // agent mutex. This is the drain fix path.
                            let cfg = cfg.read();
                            let window = cfg
                                .model_provider_context_window_opt(provider_ref)
                                .map(|v| v as u64);
                            *rw.lock().unwrap() = window;
                        }
                        TurnEvent::Chunk { .. } => {
                            *cc.lock().unwrap() += 1;
                        }
                        _ => {}
                    }
                }
            },
        )
        .await
        .expect("turn should complete without deadlocking");

        assert!(
            matches!(outcome, TurnOutcome::Completed { .. }),
            "turn must complete normally while the drain callback resolves the window from config"
        );
        assert_eq!(
            *usage_count.lock().unwrap(),
            1,
            "exactly one Usage event must drain through the callback"
        );
        assert!(
            *chunk_count.lock().unwrap() >= 1,
            "at least one Chunk event must drain AFTER the Usage event — \
             proves the callback did not stall the drain by reacquiring the agent mutex"
        );
        assert_eq!(
            *resolved_window.lock().unwrap(),
            Some(128_000),
            "the drain callback must resolve model_context_window from the \
             provider_ref via config, not the agent mutex"
        );
    }

    /// Regression: drive the **real `execute_turn` RPC
    /// boundary** with an interleaved Usage → ToolCall → ToolResult → Usage
    /// → final Chunk sequence — the exact flow production dispatch sees — and
    /// assert the drain completes every notification while `execute_turn` owns
    /// the agent lock, across the full 2×2 matrix of provider configuration:
    ///
    ///   (`max_context_tokens` ∈ {Some, None}) × (`context_window` ∈ {Some, None})
    ///
    /// The matrix is a negative control on the trim-budget axis: the drain
    /// callback resolves `model_context_window` from the embedded
    /// `provider_ref` via config (`model_provider_context_window_opt`), which
    /// returns the provider's `context_window` and ONLY that. It must never
    /// substitute the runtime profile's `max_context_tokens` budget — neither
    /// when the provider has no `context_window` (the legacy 32k stub leak) nor
    /// when the provider has one (no cross-contamination). The four cells
    /// prove the resolved window tracks the provider column exclusively,
    /// independent of the profile row.
    #[tokio::test]
    async fn execute_turn_drain_resolves_window_across_provider_config_matrix_through_tool_turn() {
        use crate::agent::agent::Agent;
        use crate::agent::dispatcher::NativeToolDispatcher;
        use crate::observability::{NoopObserver, Observer};
        use crate::tools::{Tool, ToolResult};
        use async_trait::async_trait;
        use std::sync::Arc;
        use std::sync::Mutex as StdMutex;
        use tokio::sync::Mutex;
        use zeroclaw_api::attribution::{Attributable, ModelProviderKind, ProviderKind, Role};
        use zeroclaw_api::model_provider::ModelProvider;
        use zeroclaw_memory::Memory;
        use zeroclaw_providers::ChatRequest;
        use zeroclaw_providers::traits::TokenUsage;
        use zeroclaw_providers::{ChatResponse, ToolCall};

        // ── scripted two-call provider: call 1 emits a tool call + usage,
        //    call 2 emits final text + usage. The drain must process both
        //    Usage events plus the interleaved tool events without relocking
        //    the agent (execute_turn holds agent.lock() for the whole turn).
        struct TwoCallToolProvider {
            first: ChatResponse,
            second: ChatResponse,
            done: std::sync::atomic::AtomicBool,
            alias: &'static str,
        }

        #[async_trait]
        impl ModelProvider for TwoCallToolProvider {
            async fn chat_with_system(
                &self,
                _system: Option<&str>,
                _message: &str,
                _model: &str,
                _temperature: Option<f64>,
            ) -> anyhow::Result<String> {
                Ok("ok".into())
            }

            async fn chat(
                &self,
                _request: ChatRequest<'_>,
                _model: &str,
                _temperature: Option<f64>,
            ) -> anyhow::Result<ChatResponse> {
                if !self.done.swap(true, std::sync::atomic::Ordering::SeqCst) {
                    Ok(self.first.clone())
                } else {
                    Ok(self.second.clone())
                }
            }
        }

        impl Attributable for TwoCallToolProvider {
            fn role(&self) -> Role {
                Role::Provider(ProviderKind::Model(ModelProviderKind::Custom))
            }
            fn alias(&self) -> &str {
                self.alias
            }
        }

        // ── minimal tool the provider can call. Counts invocations so the
        //    test can assert the tool actually ran exactly once between the
        //    two Usage events — proving the interleaved flow is real, not a
        //    degenerate single-call path.
        struct CountingTool {
            name: &'static str,
            calls: Arc<std::sync::atomic::AtomicUsize>,
        }

        #[async_trait]
        impl Tool for CountingTool {
            fn name(&self) -> &str {
                self.name
            }
            fn description(&self) -> &str {
                self.name
            }
            fn parameters_schema(&self) -> serde_json::Value {
                serde_json::json!({"type": "object"})
            }
            async fn execute(&self, _args: serde_json::Value) -> anyhow::Result<ToolResult> {
                self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(ToolResult {
                    success: true,
                    output: format!("{}-out", self.name).into(),
                    error: None,
                })
            }
        }

        zeroclaw_api::tool_attribution!(
            CountingTool,
            ::zeroclaw_api::attribution::ToolKind::Plugin
        );

        fn token_usage(input: u64, output: u64) -> TokenUsage {
            TokenUsage {
                input_tokens: Some(input),
                cached_input_tokens: None,
                output_tokens: Some(output),
            }
        }

        // ── provider refs and the expected resolved window per (ctx, max) cell.
        //    Each cell uses a distinct provider alias so they share no registry
        //    entry. The (max_context_tokens, context_window) matrix:
        //
        //      ┌────────────────┬──────────────────┬───────────────────┐
        //      │ max_context_   │ context_window = │ context_window =  │
        //      │ tokens         │ Some(200_000)    │ None              │
        //      ├────────────────┼──────────────────┼───────────────────┤
        //      │ Some(32_000)    │ some_some, 200k  │ some_none, None   │
        //      │ None           │ none_some, 200k  │ none_none, None   │
        //      └────────────────┴──────────────────┴───────────────────┘
        //
        //    In every cell the resolved window tracks the provider's
        //    context_window (Some → Some(200_000), None → None) and ignores
        //    max_context_tokens entirely — the negative control that proves
        //    the legacy 32k stub leak (None wrongly reported as 32_000) is gone.
        #[derive(Clone, Copy)]
        struct MatrixCell {
            label: &'static str,
            provider_ref: &'static str,
            max_context_tokens: Option<usize>,
            context_window: Option<u64>,
            expected_resolved: Option<u64>,
        }

        let cells: [MatrixCell; 4] = [
            MatrixCell {
                label: "(max=some, ctx=some)",
                provider_ref: "openai.some_some",
                max_context_tokens: Some(32_000),
                context_window: Some(200_000),
                expected_resolved: Some(200_000),
            },
            MatrixCell {
                label: "(max=some, ctx=none)",
                provider_ref: "openai.some_none",
                max_context_tokens: Some(32_000),
                context_window: None,
                expected_resolved: None,
            },
            MatrixCell {
                label: "(max=none, ctx=some)",
                provider_ref: "openai.none_some",
                max_context_tokens: None,
                context_window: Some(200_000),
                expected_resolved: Some(200_000),
            },
            MatrixCell {
                label: "(max=none, ctx=none)",
                provider_ref: "openai.none_none",
                max_context_tokens: None,
                context_window: None,
                expected_resolved: None,
            },
        ];

        for cell in cells {
            // Build a config with this provider's context_window. Each case
            // uses a distinct (type, alias) so cell configs never collide.
            let (type_key, alias_key) = cell
                .provider_ref
                .split_once('.')
                .expect("provider_ref is type.alias");
            let mut config = zeroclaw_config::schema::Config::default();
            {
                let entry = config
                    .providers
                    .models
                    .ensure(type_key, alias_key)
                    .expect("ensure provider for matrix cell");
                if let Some(window) = cell.context_window {
                    entry.context_window = Some(window as usize);
                }
            }

            let memory_cfg = zeroclaw_config::schema::MemoryConfig {
                backend: "none".into(),
                ..zeroclaw_config::schema::MemoryConfig::default()
            };
            let mem: Arc<dyn Memory> = Arc::from(
                zeroclaw_memory::create_memory(&memory_cfg, std::path::Path::new("/tmp"), None)
                    .expect("memory creation should succeed"),
            );

            // Two scripted responses: call 1 carries a tool call + usage;
            // call 2 carries final text + usage. The drain sees the full
            // interleaved sequence through the real execute_turn boundary.
            let first_usage = token_usage(10, 5);
            let second_usage = token_usage(20, 8);
            let first = ChatResponse {
                text: Some(String::new()),
                tool_calls: vec![ToolCall {
                    id: "tc-matrix".into(),
                    name: "echo".into(),
                    arguments: "{}".into(),
                    extra_content: None,
                }],
                usage: Some(first_usage),
                reasoning_content: None,
            };
            let second = ChatResponse {
                text: Some("matrix done".into()),
                tool_calls: vec![],
                usage: Some(second_usage),
                reasoning_content: None,
            };

            let provider = TwoCallToolProvider {
                first,
                second,
                done: std::sync::atomic::AtomicBool::new(false),
                alias: cell.provider_ref,
            };

            let tool_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let agent = Agent::builder()
                .model_provider(Box::new(provider))
                .tools(vec![Box::new(CountingTool {
                    name: "echo",
                    calls: Arc::clone(&tool_calls),
                })])
                .memory(mem)
                .observer(Arc::from(NoopObserver {}) as Arc<dyn Observer>)
                .tool_dispatcher(Box::new(NativeToolDispatcher))
                .workspace_dir(std::path::PathBuf::from("/tmp"))
                .model_name("matrix-model".into())
                .model_provider_name(cell.provider_ref.into())
                .agent_alias("rpc-matrix".into())
                .build()
                .expect("agent builder should succeed");

            // Per-cell counters collected by the drain callback. The callback
            // invokes model_provider_context_window_opt(&cfg.read(), provider_ref)
            // — the same config-read path production uses — proving it does not
            // reacquire the agent mutex. Each of the two Usage events records
            // its resolved window; we assert both match the cell expectation
            // (i.e., the second call's resolution is NOT polluted by the first).
            let usage_count = Arc::new(StdMutex::new(0usize));
            let tool_call_seen = Arc::new(StdMutex::new(false));
            let tool_result_seen = Arc::new(StdMutex::new(false));
            let chunk_after_second_usage = Arc::new(StdMutex::new(false));
            let resolved_windows: Arc<StdMutex<Vec<Option<u64>>>> = Arc::new(StdMutex::new(vec![]));
            let provider_refs_seen: Arc<StdMutex<Vec<String>>> = Arc::new(StdMutex::new(vec![]));
            let saw_second_usage = Arc::new(std::sync::atomic::AtomicBool::new(false));

            let cfg_for_cb: Arc<parking_lot::RwLock<zeroclaw_config::schema::Config>> =
                Arc::new(config.into());
            let cfg_arc = Arc::clone(&cfg_for_cb);
            let uc = Arc::clone(&usage_count);
            let tcs = Arc::clone(&tool_call_seen);
            let trs = Arc::clone(&tool_result_seen);
            let cfa = Arc::clone(&chunk_after_second_usage);
            let rw = Arc::clone(&resolved_windows);
            let prs = Arc::clone(&provider_refs_seen);
            let ssu = Arc::clone(&saw_second_usage);

            let outcome = execute_turn(
                Arc::new(Mutex::new(agent)),
                "matrix".to_string(),
                CancellationToken::new(),
                TurnAttribution {
                    session_key: Some("drain-matrix-test".into()),
                    agent_alias: "rpc-matrix".into(),
                    model_provider: cell.provider_ref.into(),
                    model: "matrix-model".into(),
                    channel: "rpc",
                },
                None,
                move |event| {
                    let cfg = Arc::clone(&cfg_arc);
                    let uc = Arc::clone(&uc);
                    let tcs = Arc::clone(&tcs);
                    let trs = Arc::clone(&trs);
                    let cfa = Arc::clone(&cfa);
                    let rw = Arc::clone(&rw);
                    let prs = Arc::clone(&prs);
                    let ssu = Arc::clone(&ssu);
                    async move {
                        match &event {
                            TurnEvent::Usage { provider_ref, .. } => {
                                *uc.lock().unwrap() += 1;
                                let before_second = ssu.load(std::sync::atomic::Ordering::SeqCst);
                                ssu.store(true, std::sync::atomic::Ordering::SeqCst);
                                prs.lock().unwrap().push(provider_ref.clone());
                                // Resolve model_context_window from the
                                // embedded provider_ref via config.read() —
                                // NOT via the agent mutex. This is the drain
                                // fix path; if it locked the agent again the
                                // drain would stall after the first Usage.
                                let cfg = cfg.read();
                                let window = cfg
                                    .model_provider_context_window_opt(provider_ref)
                                    .map(|v| v as u64);
                                rw.lock().unwrap().push(window);
                                // A Chunk arriving AFTER the first Usage but
                                // before the second is the normal call-1 path;
                                // we only care that a Chunk arrives after the
                                // SECOND Usage too. Reset chunk-after flag on
                                // each Usage so it only sticks on a Chunk seen
                                // after the most-recent (second) Usage.
                                if before_second {
                                    *cfa.lock().unwrap() = false;
                                }
                            }
                            TurnEvent::ToolCall { id, .. } => {
                                if id == "tc-matrix" {
                                    *tcs.lock().unwrap() = true;
                                }
                            }
                            TurnEvent::ToolResult { id, .. } => {
                                if id == "tc-matrix" {
                                    *trs.lock().unwrap() = true;
                                }
                            }
                            TurnEvent::Chunk { delta }
                                if delta.contains("matrix done")
                                    && ssu.load(std::sync::atomic::Ordering::SeqCst) =>
                            {
                                *cfa.lock().unwrap() = true;
                            }
                            _ => {}
                        }
                    }
                },
            )
            .await
            .expect("turn should complete without deadlocking across the matrix");

            // Outcome sanity: the turn completes normally (not cancelled,
            // not panicked) regardless of provider config. TurnOutcome is not
            // Debug on purpose, so match by shape.
            assert!(
                matches!(outcome, TurnOutcome::Completed { .. }),
                "{}: turn must complete normally (TurnOutcome::Completed) \
                 through execute_turn; got a non-Completed outcome \
                 (Cancelled or Err) — the drain stalled or errored",
                cell.label,
            );

            // Two Usage events (one per LLM call) drained through the callback.
            // This proves the drain continued past the first Usage AND through
            // the interleaved tool events to the second Usage — a relock stall
            // after the first Usage would prevent the second from arriving.
            assert_eq!(
                *usage_count.lock().unwrap(),
                2,
                "{}: exactly two Usage events must drain through the callback \
                 (one per LLM call); a relock would stall after the first",
                cell.label,
            );

            // Both Usage events carry the cell's serving provider_ref — the
            // coherent-tuple invariant exercised at the
            // RPC boundary, not just the agent-internal steering-state path.
            let refs: Vec<String> = provider_refs_seen.lock().unwrap().clone();
            assert_eq!(
                refs.len(),
                2,
                "{}: expected two provider_ref observations, got {:?}",
                cell.label,
                refs,
            );
            assert!(
                refs.iter().all(|r| r == cell.provider_ref),
                "{}: every Usage event's provider_ref must be `{}`, got {:?}",
                cell.label,
                cell.provider_ref,
                refs,
            );

            // The interleaved tool turn is real: the tool actually ran once
            // between the two Usage events, and both ToolCall and ToolResult
            // notifications were observed through the real RPC callback.
            assert!(
                *tool_call_seen.lock().unwrap(),
                "{}: ToolCall event must drain through the callback",
                cell.label,
            );
            assert!(
                *tool_result_seen.lock().unwrap(),
                "{}: ToolResult event must drain through the callback",
                cell.label,
            );
            assert_eq!(
                tool_calls.load(std::sync::atomic::Ordering::SeqCst),
                1,
                "{}: the echo tool must run exactly once between the two \
                 Usage events",
                cell.label,
            );

            // Final Chunk arrived AFTER the second Usage — the drain processed
            // the whole interleaved sequence without stalling.
            assert!(
                *chunk_after_second_usage.lock().unwrap(),
                "{}: a final Chunk must arrive after the second Usage event, \
                 proving the drain did not stall at the RPC callback boundary",
                cell.label,
            );

            // The matrix core: in every cell, model_provider_context_window_opt
            // returns the PROVIDER's context_window and ONLY that — never the
            // profile's max_context_tokens. Both Usage events in the cell
            // resolve identically (the resolution is deterministic per
            // provider_ref and not stateful across calls).
            let windows: Vec<Option<u64>> = resolved_windows.lock().unwrap().clone();
            assert_eq!(
                windows.len(),
                2,
                "{}: expected two resolved-window observations, got {:?}",
                cell.label,
                windows,
            );
            for (i, w) in windows.iter().enumerate() {
                assert_eq!(
                    *w,
                    cell.expected_resolved,
                    "{}: Usage #{} resolved model_context_window = {:?}, \
                     expected {:?} (provider context_window = {:?}, profile \
                     max_context_tokens = {:?}); the drain callback must \
                     resolve the live provider window via config, never \
                     substitute the trim budget when the provider has none, \
                     and never cross-contaminate when it has one",
                    cell.label,
                    i + 1,
                    w,
                    cell.expected_resolved,
                    cell.context_window,
                    cell.max_context_tokens,
                );
            }
        }
    }
}
