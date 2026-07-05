use super::outcome::is_tool_loop_cancelled;
use crate::agent::history::estimate_history_tokens;
use crate::agent::history_trim::trim_to_recent_turns;
use crate::observability::{Observer, ObserverEvent};
use std::time::Instant;
use zeroclaw_providers::ChatMessage;

/// Record a failed provider call: observer `LlmResponse` (failure) and the
/// `llm_response` failure log line.
pub(crate) fn record_llm_failure(
    ctx: &super::context::TurnCtx<'_>,
    llm_started_at: Instant,
    iteration: usize,
    e: &anyhow::Error,
) {
    // User cancellation gets the fixed message the streaming consumers have
    // always seen (and pin), never a raw error string.
    let safe_error = if is_tool_loop_cancelled(e) {
        "request cancelled by user".to_string()
    } else {
        zeroclaw_providers::sanitize_api_error(&e.to_string())
    };
    ctx.observer.record_event(&ObserverEvent::LlmResponse {
        model_provider: ctx.provider_name.to_string(),
        model: ctx.model.to_string(),
        duration: llm_started_at.elapsed(),
        success: false,
        error_message: Some(safe_error.clone()),
        input_tokens: None,
        output_tokens: None,
        channel: Some(ctx.channel_name.to_string()),
        agent_alias: ctx.agent_alias.map(|s| s.to_string()),
        turn_id: Some(ctx.turn_id.to_string()),
        // Error path: no prompt/completion content captured.
        messages: None,
    });
    ::zeroclaw_log::record!(
        WARN,
        ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Fail)
            .with_category(::zeroclaw_log::EventCategory::Provider)
            .with_outcome(::zeroclaw_log::EventOutcome::Failure)
            .with_duration(u64::try_from(llm_started_at.elapsed().as_millis()).unwrap_or(u64::MAX))
            .with_attrs(::serde_json::json!({
                "model": ctx.model,
                "iteration": iteration + 1,
                "error": safe_error,
                "trace_id": ctx.turn_id,
            })),
        "llm_response"
    );
}

/// Context overflow recovery: trim history and retry.
///
/// Returns `true` when the history was trimmed and the caller should
/// `continue` the loop; the orchestrator keeps
/// `if recovered { continue; } return Err(e);` inline.
///
/// Emits `TurnEvent::HistoryTrimmed` and `ObserverEvent::HistoryTrimmed` on the
/// trimmed branch so the 400-recovery cut is never silent to ACP / WS / SSE
/// subscribers, matching the preemptive turn-boundary path.
pub(crate) async fn try_recover_context_overflow(
    history: &mut Vec<ChatMessage>,
    e: &anyhow::Error,
    iteration: Option<usize>,
    provider_name: &str,
    model: &str,
    channel_name: &str,
    agent_alias: Option<&str>,
    turn_id: &str,
    event_tx: Option<&tokio::sync::mpsc::Sender<zeroclaw_api::agent::TurnEvent>>,
    observer: &dyn Observer,
) -> bool {
    if !zeroclaw_providers::reliable::is_context_window_exceeded(e) {
        return false;
    }

    // Enter span only for the WARN log, drop before any await
    {
        let _span = ::zeroclaw_log::info_span!(
            target: "zeroclaw_log_internal_scope",
            "zeroclaw_scope",
            model = %model,
            model_provider = %provider_name,
        )
        .entered();

        let mut attrs = ::serde_json::json!({});
        if let Some(iter) = iteration {
            attrs = ::serde_json::json!({"iteration": iter + 1});
        }
        ::zeroclaw_log::record!(
            WARN,
            ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Retry)
                .with_category(::zeroclaw_log::EventCategory::Agent)
                .with_attrs(attrs),
            "Context window exceeded, attempting in-loop recovery"
        );
    }

    // One rule: drop oldest whole turns until we are under a budget
    // forced below the current size. Never splits a tool_use/tool_result
    // pair, never silently shrinks a result. Whole turns or nothing.
    let tokens_now = estimate_history_tokens(history);
    let budget = tokens_now.saturating_mul(2) / 3;
    let owned = std::mem::take(history);
    let result = trim_to_recent_turns(owned, budget);
    let trimmed = result.trimmed;
    let dropped_turns = result.dropped_turns;
    let dropped_messages = result.dropped_messages;
    let kept_turns = result.kept_turns;
    let tokens_after = result.tokens_after;
    let mut recovered_history = result.history;
    if trimmed {
        // Insert the same model-visible breadcrumb the turn-boundary path
        // uses, after the leading system messages, so the retried provider
        // call tells the model earlier turns were dropped (never silent to
        // the model, not just to clients).
        let system_count = recovered_history
            .iter()
            .take_while(|m| m.role == "system")
            .count();
        recovered_history.insert(system_count, crate::agent::history_trim::breadcrumb());
    }
    *history = recovered_history;
    if trimmed {
        // Enter span only for the INFO log, drop before any await
        {
            let _span = ::zeroclaw_log::info_span!(
                target: "zeroclaw_log_internal_scope",
                "zeroclaw_scope",
                model = %model,
                model_provider = %provider_name,
            )
            .entered();

            ::zeroclaw_log::record!(
                INFO,
                ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Retry)
                    .with_category(::zeroclaw_log::EventCategory::Agent)
                    .with_attrs(::serde_json::json!({
                        "dropped_turns": dropped_turns,
                        "dropped_messages": dropped_messages,
                        "kept_turns": kept_turns,
                        "tokens_before": tokens_now,
                        "tokens_after": tokens_after,
                    })),
                "Context recovery: dropped oldest whole turns, retrying"
            );
        }
        let reason = crate::i18n::get_required_cli_string("history-trim-reason-budget");
        if let Some(tx) = event_tx {
            let _ = tx
                .send(zeroclaw_api::agent::TurnEvent::HistoryTrimmed {
                    dropped_messages,
                    kept_turns,
                    reason: reason.clone(),
                })
                .await;
        }
        observer.record_event(&ObserverEvent::HistoryTrimmed {
            dropped_messages,
            kept_turns,
            reason,
            channel: Some(channel_name.to_string()),
            agent_alias: agent_alias.map(|s| s.to_string()),
            turn_id: Some(turn_id.to_string()),
        });
        return true;
    }

    // Nothing left to trim — truly unrecoverable
    ::zeroclaw_log::record!(
        ERROR,
        ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Fail)
            .with_category(::zeroclaw_log::EventCategory::Agent)
            .with_outcome(::zeroclaw_log::EventOutcome::Failure),
        "Context overflow unrecoverable: only one turn left, cannot trim further"
    );
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observability::NoopObserver;
    use zeroclaw_providers::ChatMessage;

    fn overflowing_history() -> Vec<ChatMessage> {
        let big = "x".repeat(4000);
        let mut h = vec![ChatMessage::system("system")];
        for i in 0..6 {
            h.push(ChatMessage::user(format!("turn {i} {big}").as_str()));
            h.push(ChatMessage::assistant(format!("reply {i} {big}").as_str()));
        }
        h
    }

    #[tokio::test]
    async fn recovery_emits_history_trimmed_event_on_trim() {
        let mut history = overflowing_history();
        let err = anyhow::Error::msg("maximum context length exceeded");
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let observer = NoopObserver;

        let recovered = try_recover_context_overflow(
            &mut history,
            &err,
            Some(1),
            "test-provider",
            "test-model",
            "test-channel",
            None,
            "recovery-test",
            Some(&tx),
            &observer,
        )
        .await;

        assert!(recovered, "an overflowing history must trim and recover");
        // The retried history must carry the model-visible breadcrumb after the
        // leading system messages, matching the turn-boundary contract.
        let breadcrumb_text = crate::i18n::get_required_cli_string("history-trim-breadcrumb");
        assert!(
            history.iter().any(|m| m.content == breadcrumb_text),
            "recovery must insert the breadcrumb so the model sees the trim"
        );
        let event = rx.try_recv().expect("recovery must emit a TurnEvent");
        match event {
            zeroclaw_api::agent::TurnEvent::HistoryTrimmed {
                dropped_messages,
                kept_turns,
                reason,
            } => {
                assert!(dropped_messages > 0, "must report dropped messages");
                assert!(kept_turns >= 1, "must keep at least the current turn");
                assert_eq!(
                    reason,
                    crate::i18n::get_required_cli_string("history-trim-reason-budget")
                );
            }
            other => panic!("expected HistoryTrimmed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn non_overflow_error_is_not_recovered_and_emits_nothing() {
        let mut history = overflowing_history();
        let err = anyhow::Error::msg("some unrelated provider error");
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let observer = NoopObserver;

        let recovered = try_recover_context_overflow(
            &mut history,
            &err,
            Some(1),
            "test-provider",
            "test-model",
            "test-channel",
            None,
            "recovery-test",
            Some(&tx),
            &observer,
        )
        .await;

        assert!(!recovered, "a non-overflow error must not trigger recovery");
        assert!(rx.try_recv().is_err(), "no event on the non-overflow path");
    }

    #[tokio::test]
    async fn recovery_budget_is_two_thirds_of_current_tokens() {
        let mut history = overflowing_history();
        let err = anyhow::Error::msg("maximum context length exceeded");
        let (tx, _rx) = tokio::sync::mpsc::channel(8);
        let observer = NoopObserver;

        let tokens_before = crate::agent::history::estimate_history_tokens(&history);
        let recovered = try_recover_context_overflow(
            &mut history,
            &err,
            Some(1),
            "test-provider",
            "test-model",
            "test-channel",
            None,
            "recovery-test",
            Some(&tx),
            &observer,
        )
        .await;

        assert!(recovered, "an overflowing history must trim and recover");
        let tokens_after = crate::agent::history::estimate_history_tokens(&history);
        let expected_max = tokens_before.saturating_mul(2) / 3;
        assert!(
            tokens_after <= expected_max,
            "recovery must trim to at most 2/3 of pre-recovery tokens (before={}, after={}, max={})",
            tokens_before,
            tokens_after,
            expected_max
        );
    }

    #[tokio::test]
    async fn recovery_observer_event_carries_real_ctx_values() {
        use crate::observability::traits::{Observer, ObserverEvent, ObserverMetric};
        use std::any::Any;
        use std::sync::{Arc, Mutex};

        struct RecordingObserver {
            events: Arc<Mutex<Vec<ObserverEvent>>>,
        }

        impl RecordingObserver {
            fn new() -> Self {
                Self {
                    events: Arc::new(Mutex::new(Vec::new())),
                }
            }
        }

        impl Observer for RecordingObserver {
            fn record_event(&self, event: &ObserverEvent) {
                self.events.lock().unwrap().push(event.clone());
            }

            fn record_metric(&self, _metric: &ObserverMetric) {}

            fn name(&self) -> &str {
                "test-recording"
            }

            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let mut history = overflowing_history();
        let err = anyhow::Error::msg("maximum context length exceeded");
        let (tx, _rx) = tokio::sync::mpsc::channel(8);
        let observer = RecordingObserver::new();

        let recovered = try_recover_context_overflow(
            &mut history,
            &err,
            Some(1),
            "my-provider",
            "my-model",
            "my-channel",
            Some("my-agent"),
            "my-turn-id",
            Some(&tx),
            &observer,
        )
        .await;

        assert!(recovered, "an overflowing history must trim and recover");

        let events = observer.events.lock().unwrap();
        let trimmed_event = events
            .iter()
            .find(|e| matches!(e, ObserverEvent::HistoryTrimmed { .. }))
            .expect("recovery must emit ObserverEvent::HistoryTrimmed");

        match trimmed_event {
            ObserverEvent::HistoryTrimmed {
                channel,
                agent_alias,
                turn_id,
                ..
            } => {
                assert_eq!(channel.as_deref(), Some("my-channel"));
                assert_eq!(agent_alias.as_deref(), Some("my-agent"));
                assert_eq!(turn_id.as_deref(), Some("my-turn-id"));
            }
            _ => panic!("expected HistoryTrimmed"),
        }
    }

    #[tokio::test]
    async fn recovery_returns_false_when_only_one_turn_remains() {
        // Create a history with just one user-assistant turn that is very large
        // so it cannot be trimmed further (would leave empty history)
        let big = "x".repeat(50000);
        let mut history = vec![
            ChatMessage::system("system"),
            ChatMessage::user(&big),
            ChatMessage::assistant(&big),
        ];
        let err = anyhow::Error::msg("maximum context length exceeded");
        let (tx, _rx) = tokio::sync::mpsc::channel(8);
        let observer = NoopObserver;

        // Should return false because we can't trim the only remaining turn
        let recovered = try_recover_context_overflow(
            &mut history,
            &err,
            Some(1),
            "test-provider",
            "test-model",
            "test-channel",
            None,
            "recovery-test",
            Some(&tx),
            &observer,
        )
        .await;

        assert!(!recovered, "recovery must fail when only one turn remains");
        // History should be unchanged
        assert_eq!(
            history.len(),
            3,
            "history must not be modified when unrecoverable"
        );
    }
}
