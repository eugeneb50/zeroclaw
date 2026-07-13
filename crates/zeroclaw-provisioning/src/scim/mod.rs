//! SCIM 2.0 (RFC 7643/7644) implementation.
//!
//! Provides types, filter parsing, and client for inbound provisioning from IdPs.

pub mod schema;
pub mod filter;
pub mod client;

pub use schema::{
    ScimUser, ScimGroup, ScimListResponse, ScimMeta, ScimServiceProviderConfig,
    ScimEnterpriseUser, ScimEmail, ScimPhoneNumber, ScimAddress,
    ScimGroupRef, ScimMember, ScimEntitlement, ScimRole, ScimCertificate,
    ScimIm, ScimPhoto,
    // ZeroClaw custom resources
    ScimChannel, ScimChannelBinding, ScimAgent, ScimSkill, ScimCronJob,
    ScimTool, ScimMemory, ScimModelProvider, ScimPeerGroup, ScimRuntimeConfig,
    ScimPeripheral,
};
pub use filter::{ScimFilter, ComparisonOp, FilterValue, FilterError, parse_filter};
pub use client::ScimClient;