//! Shared test utilities for integration tests.

#![allow(dead_code, unused_imports)]

pub mod assertions;
pub mod helpers;
pub mod mock_channel;
pub mod mock_model_provider;
pub mod mock_tools;
pub mod trace;
pub mod test_utils;

pub use mock_model_provider::{MockModelProvider, RecordingModelProvider};
pub use mock_tools::{CountingTool, EchoTool, FailingTool, RecordingTool};
pub use test_utils::{
    TestIdP, make_oidc_principal, make_operator_principal,
    wait_for_sync_event, assert_authenticated, assert_denied, make_operator_grants,
};