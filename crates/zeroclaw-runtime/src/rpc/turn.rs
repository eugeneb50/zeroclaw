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
                            let window =
                                crate::agent::resolve_live_model_context_window(&cfg, provider_ref);
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
}
