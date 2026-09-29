use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use thiserror::Error;

pub const TRACE_SCHEMA_VERSION: &str = "solana-debug/trace@0.1";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TraceError {
    #[error("duplicate invocation id: {0}")]
    DuplicateInvocationId(String),
    #[error("child invocation {child} references unknown parent {parent}")]
    UnknownParent { child: String, parent: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TraceSource {
    Rpc,
    RawTransaction,
    Bundle,
    Fixture,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", tag = "kind", content = "value")]
pub enum TransactionVersion {
    Legacy,
    V0,
    V1,
    Unknown(u8),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TraceQuality {
    Complete,
    Partial,
    Ambiguous,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum AccountSource {
    Static,
    AddressLookupTable { table: String, writable: bool },
    V1Inline,
    RpcSnapshot,
    Fixture,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountDataRef {
    pub sha256: String,
    pub length: usize,
    pub decoded_type: Option<String>,
    pub redacted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountInfo {
    pub index: usize,
    pub pubkey: String,
    pub is_signer: bool,
    pub is_writable: bool,
    pub source: AccountSource,
    pub owner: Option<String>,
    pub executable: Option<bool>,
    pub lamports: Option<u64>,
    pub space: Option<u64>,
    pub data: Option<AccountDataRef>,
    pub snapshot_slot: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecodedInstruction {
    pub program: String,
    pub name: String,
    pub details: TraceValue,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProgramLog {
    pub invocation_id: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReturnData {
    pub program_id: String,
    pub data_base64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ComputeSummary {
    pub units_consumed: Option<u64>,
    pub requested_units: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionError {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AddressLookup {
    pub table: String,
    pub writable: Vec<String>,
    pub readonly: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransactionConfig {
    pub requested_compute_units: Option<u64>,
    pub loaded_accounts_data_size_limit: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceProvenance {
    pub collected_by: String,
    pub rpc_url: Option<String>,
    pub commitment: Option<String>,
    pub historical_state_complete: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InvocationStatus {
    Succeeded,
    Failed,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InvocationNode {
    pub id: String,
    pub top_level_instruction: usize,
    pub parent_id: Option<String>,
    pub stack_height: u32,
    pub program_id: String,
    pub account_indices: Vec<usize>,
    pub account_pubkeys: Vec<String>,
    pub raw_data_base64: String,
    pub decoded: Option<DecodedInstruction>,
    pub logs: Vec<String>,
    pub status: InvocationStatus,
    pub error: Option<ExecutionError>,
    pub children: Vec<InvocationNode>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransactionTrace {
    pub schema_version: String,
    pub source: TraceSource,
    pub signature: Option<String>,
    pub slot: Option<u64>,
    pub block_time: Option<i64>,
    pub transaction_version: TransactionVersion,
    pub wire_sha256: String,
    pub success: bool,
    pub fee_payer: String,
    pub accounts: Vec<AccountInfo>,
    pub invocations: Vec<InvocationNode>,
    pub logs: Vec<ProgramLog>,
    pub return_data: Option<ReturnData>,
    pub compute: ComputeSummary,
    pub error: Option<ExecutionError>,
    pub address_lookups: Vec<AddressLookup>,
    pub transaction_config: Option<TransactionConfig>,
    pub provenance: TraceProvenance,
    pub trace_quality: TraceQuality,
}

impl TransactionTrace {
    pub fn validate(&self) -> Result<(), TraceError> {
        let mut ids = HashSet::new();
        collect_ids(&self.invocations, &mut ids)?;
        validate_parents(&self.invocations, &ids)
    }

    pub fn failing_invocation(&self) -> Option<&InvocationNode> {
        self.invocations.iter().find_map(find_failing_invocation)
    }
}

fn collect_ids(nodes: &[InvocationNode], ids: &mut HashSet<String>) -> Result<(), TraceError> {
    for node in nodes {
        if !ids.insert(node.id.clone()) {
            return Err(TraceError::DuplicateInvocationId(node.id.clone()));
        }
        collect_ids(&node.children, ids)?;
    }
    Ok(())
}

fn validate_parents(nodes: &[InvocationNode], ids: &HashSet<String>) -> Result<(), TraceError> {
    for node in nodes {
        if let Some(parent) = &node.parent_id {
            if !ids.contains(parent) {
                return Err(TraceError::UnknownParent {
                    child: node.id.clone(),
                    parent: parent.clone(),
                });
            }
        }
        validate_parents(&node.children, ids)?;
    }
    Ok(())
}

fn find_failing_invocation(node: &InvocationNode) -> Option<&InvocationNode> {
    if let Some(child) = node.children.iter().find_map(find_failing_invocation) {
        return Some(child);
    }

    if node.status == InvocationStatus::Failed {
        return Some(node);
    }

    None
}

pub mod serde_like {
    use serde::{Deserialize, Serialize};
    use std::collections::BTreeMap;

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(untagged)]
    pub enum Value {
        Null,
        Bool(bool),
        Number(i64),
        String(String),
        Array(Vec<Value>),
        Object(BTreeMap<String, Value>),
    }
}

pub use serde_like::Value as TraceValue;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_round_trips_and_validates() {
        let raw = include_str!("../../../fixtures/trace/failing-token-program-mismatch.json");
        let trace: TransactionTrace = serde_json::from_str(raw).unwrap();

        assert_eq!(trace.schema_version, TRACE_SCHEMA_VERSION);
        assert_eq!(trace.validate(), Ok(()));
        assert_eq!(
            trace.failing_invocation().map(|node| node.id.as_str()),
            Some("2.1")
        );
    }

    #[test]
    fn duplicate_invocation_ids_are_rejected() {
        let node = InvocationNode {
            id: "1".to_string(),
            top_level_instruction: 1,
            parent_id: None,
            stack_height: 1,
            program_id: "Example111111111111111111111111111111111111".to_string(),
            account_indices: vec![],
            account_pubkeys: vec![],
            raw_data_base64: String::new(),
            decoded: None,
            logs: vec![],
            status: InvocationStatus::Unknown,
            error: None,
            children: vec![],
        };
        let trace = TransactionTrace {
            schema_version: TRACE_SCHEMA_VERSION.to_string(),
            source: TraceSource::Fixture,
            signature: None,
            slot: None,
            block_time: None,
            transaction_version: TransactionVersion::V0,
            wire_sha256: "sha256:test".to_string(),
            success: true,
            fee_payer: "payer".to_string(),
            accounts: vec![],
            invocations: vec![node.clone(), node],
            logs: vec![],
            return_data: None,
            compute: ComputeSummary {
                units_consumed: None,
                requested_units: None,
            },
            error: None,
            address_lookups: vec![],
            transaction_config: None,
            provenance: TraceProvenance {
                collected_by: "test".to_string(),
                rpc_url: None,
                commitment: None,
                historical_state_complete: false,
            },
            trace_quality: TraceQuality::Ambiguous,
        };

        assert!(matches!(
            trace.validate(),
            Err(TraceError::DuplicateInvocationId(id)) if id == "1"
        ));
    }
}
