//! Miscellaneous subsystems extracted from the root crate.
//! Security, observability, gateway, cron, SOP, skills, hardware, and more.

pub mod cli_input;
pub mod i18n;
pub mod identity;
pub mod migration;
pub mod util;

pub mod approval;
pub mod cost;
pub mod cron;
pub mod hardware;
pub mod health;
pub mod heartbeat;
pub mod hooks;
pub mod integrations;
pub mod nodes;
pub mod observability;
pub mod onboard;
pub mod peripherals;
pub mod plugins;
pub mod rag;
pub mod routines;
pub mod runtime;
pub mod security;
pub mod service;
pub mod skillforge;
pub mod skills;
pub mod sop;
pub mod trust;
pub mod tui;
pub mod tunnel;
pub mod verifiable_intent;
