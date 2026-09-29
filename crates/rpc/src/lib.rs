use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use thiserror::Error;
use trace::{
    AccountInfo, AccountSource, AddressLookup, ComputeSummary, ExecutionError, InvocationNode,
    InvocationStatus, ProgramLog, ReturnData, TraceProvenance, TraceQuality, TraceSource,
    TransactionConfig, TransactionTrace, TransactionVersion, TRACE_SCHEMA_VERSION,
};

#[derive(Debug, Error)]
pub enum RpcIngestError {
    #[error("http rpc request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("rpc returned an error: {0}")]
    Rpc(String),
    #[error("transaction was not found")]
    TransactionNotFound,
    #[error("missing field: {0}")]
    MissingField(&'static str),
    #[error("invalid field {field}: {reason}")]
    InvalidField { field: &'static str, reason: String },
    #[error("json decode failed: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone)]
pub struct RpcIngestConfig {
    pub rpc_url: String,
    pub commitment: String,
    pub max_supported_transaction_version: u8,
}

impl RpcIngestConfig {
    pub fn new(rpc_url: String, commitment: String) -> Self {
        Self {
            rpc_url,
            commitment,
            max_supported_transaction_version: 1,
        }
    }
}

#[derive(Debug, Deserialize)]
struct RpcEnvelope {
    result: Option<Value>,
    error: Option<Value>,
}

#[derive(Debug, Serialize)]
struct GetTransactionConfig<'a> {
    encoding: &'static str,
    commitment: &'a str,
    #[serde(rename = "maxSupportedTransactionVersion")]
    max_supported_transaction_version: u8,
}

pub fn fetch_transaction_trace(
    signature: &str,
    config: &RpcIngestConfig,
) -> Result<TransactionTrace, RpcIngestError> {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getTransaction",
        "params": [
            signature,
            GetTransactionConfig {
                encoding: "json",
                commitment: &config.commitment,
                max_supported_transaction_version: config.max_supported_transaction_version,
            }
        ]
    });

    let envelope: RpcEnvelope = reqwest::blocking::Client::new()
        .post(&config.rpc_url)
        .json(&body)
        .send()?
        .error_for_status()?
        .json()?;

    let result = extract_result(envelope)?;
    transaction_trace_from_rpc_result(&result, signature, Some(config))
}

pub fn transaction_trace_from_rpc_response(
    response: &Value,
    fallback_signature: Option<&str>,
) -> Result<TransactionTrace, RpcIngestError> {
    let envelope: RpcEnvelope = serde_json::from_value(response.clone())?;
    let result = extract_result(envelope)?;
    transaction_trace_from_rpc_result(&result, fallback_signature.unwrap_or_default(), None)
}

fn extract_result(envelope: RpcEnvelope) -> Result<Value, RpcIngestError> {
    if let Some(error) = envelope.error {
        return Err(RpcIngestError::Rpc(error.to_string()));
    }

    match envelope.result {
        Some(Value::Null) | None => Err(RpcIngestError::TransactionNotFound),
        Some(result) => Ok(result),
    }
}

fn transaction_trace_from_rpc_result(
    result: &Value,
    fallback_signature: &str,
    config: Option<&RpcIngestConfig>,
) -> Result<TransactionTrace, RpcIngestError> {
    let transaction = result
        .get("transaction")
        .ok_or(RpcIngestError::MissingField("transaction"))?;
    let message = transaction
        .get("message")
        .ok_or(RpcIngestError::MissingField("transaction.message"))?;
    let meta = result.get("meta").and_then(Value::as_object);
    let slot = result.get("slot").and_then(Value::as_u64);
    let signature = transaction
        .get("signatures")
        .and_then(Value::as_array)
        .and_then(|signatures| signatures.first())
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .or_else(|| (!fallback_signature.is_empty()).then_some(fallback_signature))
        .map(ToString::to_string);

    let static_keys = string_array(
        message
            .get("accountKeys")
            .ok_or(RpcIngestError::MissingField(
                "transaction.message.accountKeys",
            ))?,
        "transaction.message.accountKeys",
    )?;
    let header = MessageHeader::from_message(message)?;
    let loaded = LoadedAddresses::from_meta(meta);
    let account_keys = canonical_account_keys(&static_keys, &loaded);
    let accounts = build_accounts(&static_keys, &loaded, &header);
    let instructions = message
        .get("instructions")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let inner_groups = meta
        .and_then(|meta| meta.get("innerInstructions"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let log_messages = meta
        .and_then(|meta| meta.get("logMessages"))
        .and_then(Value::as_array)
        .map(|logs| {
            logs.iter()
                .filter_map(Value::as_str)
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let transaction_error = meta
        .and_then(|meta| meta.get("err"))
        .filter(|err| !err.is_null());
    let failed_top_level_index = transaction_error.and_then(failed_instruction_index);
    let failed_program_id = failed_program_from_logs(&log_messages);
    let mut quality = TraceQuality::Complete;

    if meta.is_none() {
        quality = TraceQuality::Partial;
    }
    if log_messages.is_empty() {
        quality = worsen(quality, TraceQuality::Partial);
    }

    let invocations = build_invocations(
        &instructions,
        &inner_groups,
        &account_keys,
        failed_top_level_index,
        failed_program_id.as_deref(),
        &mut quality,
    )?;
    let logs = assign_logs(&log_messages);
    let return_data = meta
        .and_then(|meta| meta.get("returnData"))
        .and_then(parse_return_data);
    let transaction_version = parse_transaction_version(result.get("version"));
    let fee_payer = static_keys.first().cloned().unwrap_or_default();

    Ok(TransactionTrace {
        schema_version: TRACE_SCHEMA_VERSION.to_string(),
        source: TraceSource::Rpc,
        signature,
        slot,
        block_time: result.get("blockTime").and_then(Value::as_i64),
        transaction_version,
        wire_sha256: sha256_json(transaction),
        success: transaction_error.is_none(),
        fee_payer,
        accounts,
        invocations,
        logs,
        return_data,
        compute: ComputeSummary {
            units_consumed: meta
                .and_then(|meta| meta.get("computeUnitsConsumed"))
                .and_then(Value::as_u64),
            requested_units: None,
        },
        error: transaction_error.map(normalize_error),
        address_lookups: loaded.to_address_lookups(),
        transaction_config: Some(TransactionConfig {
            requested_compute_units: None,
            loaded_accounts_data_size_limit: None,
        }),
        provenance: TraceProvenance {
            collected_by: "solana-debug-rpc".to_string(),
            rpc_url: config.map(|config| config.rpc_url.clone()),
            commitment: config.map(|config| config.commitment.clone()),
            historical_state_complete: false,
        },
        trace_quality: quality,
    })
}

#[derive(Debug)]
struct MessageHeader {
    num_required_signatures: usize,
    num_readonly_signed_accounts: usize,
    num_readonly_unsigned_accounts: usize,
}

impl MessageHeader {
    fn from_message(message: &Value) -> Result<Self, RpcIngestError> {
        let header = message
            .get("header")
            .ok_or(RpcIngestError::MissingField("transaction.message.header"))?;
        Ok(Self {
            num_required_signatures: usize_field(header, "numRequiredSignatures")?,
            num_readonly_signed_accounts: usize_field(header, "numReadonlySignedAccounts")?,
            num_readonly_unsigned_accounts: usize_field(header, "numReadonlyUnsignedAccounts")?,
        })
    }

    fn is_signer(&self, index: usize) -> bool {
        index < self.num_required_signatures
    }

    fn is_writable(&self, index: usize, static_len: usize) -> bool {
        if self.is_signer(index) {
            let readonly_start = self
                .num_required_signatures
                .saturating_sub(self.num_readonly_signed_accounts);
            index < readonly_start
        } else {
            let readonly_start = static_len.saturating_sub(self.num_readonly_unsigned_accounts);
            index < readonly_start
        }
    }
}

#[derive(Debug, Default)]
struct LoadedAddresses {
    writable: Vec<String>,
    readonly: Vec<String>,
}

impl LoadedAddresses {
    fn from_meta(meta: Option<&serde_json::Map<String, Value>>) -> Self {
        let Some(loaded) = meta
            .and_then(|meta| meta.get("loadedAddresses"))
            .and_then(Value::as_object)
        else {
            return Self::default();
        };

        Self {
            writable: loaded
                .get("writable")
                .and_then(Value::as_array)
                .map(|values| string_array_lossy(values))
                .unwrap_or_default(),
            readonly: loaded
                .get("readonly")
                .and_then(Value::as_array)
                .map(|values| string_array_lossy(values))
                .unwrap_or_default(),
        }
    }

    fn to_address_lookups(&self) -> Vec<AddressLookup> {
        if self.writable.is_empty() && self.readonly.is_empty() {
            return Vec::new();
        }

        vec![AddressLookup {
            table: "rpc.loadedAddresses".to_string(),
            writable: self.writable.clone(),
            readonly: self.readonly.clone(),
        }]
    }
}

fn build_accounts(
    static_keys: &[String],
    loaded: &LoadedAddresses,
    header: &MessageHeader,
) -> Vec<AccountInfo> {
    let mut accounts = Vec::new();
    for (index, pubkey) in static_keys.iter().enumerate() {
        accounts.push(AccountInfo {
            index,
            pubkey: pubkey.clone(),
            is_signer: header.is_signer(index),
            is_writable: header.is_writable(index, static_keys.len()),
            source: AccountSource::Static,
            owner: None,
            executable: None,
            lamports: None,
            space: None,
            data: None,
            snapshot_slot: None,
        });
    }

    let mut index = static_keys.len();
    for pubkey in &loaded.writable {
        accounts.push(loaded_account(index, pubkey, true));
        index += 1;
    }
    for pubkey in &loaded.readonly {
        accounts.push(loaded_account(index, pubkey, false));
        index += 1;
    }

    accounts
}

fn loaded_account(index: usize, pubkey: &str, writable: bool) -> AccountInfo {
    AccountInfo {
        index,
        pubkey: pubkey.to_string(),
        is_signer: false,
        is_writable: writable,
        source: AccountSource::AddressLookupTable {
            table: "rpc.loadedAddresses".to_string(),
            writable,
        },
        owner: None,
        executable: None,
        lamports: None,
        space: None,
        data: None,
        snapshot_slot: None,
    }
}

fn build_invocations(
    instructions: &[Value],
    inner_groups: &[Value],
    account_keys: &[String],
    failed_top_level_index: Option<usize>,
    failed_program_id: Option<&str>,
    quality: &mut TraceQuality,
) -> Result<Vec<InvocationNode>, RpcIngestError> {
    let grouped_inner = group_inner_instructions(inner_groups);
    let mut nodes = Vec::new();

    for (index, instruction) in instructions.iter().enumerate() {
        let program_id_index = usize_field(instruction, "programIdIndex")?;
        let program_id = account_key(account_keys, program_id_index)?;
        let mut status = InvocationStatus::Succeeded;
        let mut error = None;
        if failed_top_level_index == Some(index) {
            status = InvocationStatus::Failed;
            error = Some(ExecutionError {
                code: "instruction_error".to_string(),
                message: "top-level instruction failed".to_string(),
            });
        }

        let mut node = instruction_node(NodeSpec {
            id: index.to_string(),
            top_level_instruction: index,
            parent_id: None,
            stack_height: 1,
            program_id,
            instruction,
            account_keys,
            status,
            error,
        })?;

        if let Some(inner) = grouped_inner.get(&index) {
            node.children = build_inner_nodes(
                index,
                &node.id,
                inner,
                account_keys,
                failed_program_id,
                quality,
            )?;
            if node.status != InvocationStatus::Failed
                && node
                    .children
                    .iter()
                    .any(|child| child.status == InvocationStatus::Failed)
            {
                node.status = InvocationStatus::Failed;
            }
        }

        nodes.push(node);
    }

    Ok(nodes)
}

fn build_inner_nodes(
    top_level_index: usize,
    top_level_id: &str,
    inner: &[Value],
    account_keys: &[String],
    failed_program_id: Option<&str>,
    quality: &mut TraceQuality,
) -> Result<Vec<InvocationNode>, RpcIngestError> {
    let has_complete_stack_height = inner.iter().all(|instruction| {
        instruction
            .get("stackHeight")
            .and_then(Value::as_u64)
            .is_some()
    });

    if !has_complete_stack_height {
        *quality = worsen(quality.clone(), TraceQuality::Partial);
        return inner
            .iter()
            .enumerate()
            .map(|(position, instruction)| {
                let program_id =
                    account_key(account_keys, usize_field(instruction, "programIdIndex")?)?;
                let failed = failed_program_id == Some(program_id.as_str());
                instruction_node(NodeSpec {
                    id: format!("{top_level_id}.{}", position + 1),
                    top_level_instruction: top_level_index,
                    parent_id: Some(top_level_id.to_string()),
                    stack_height: 2,
                    program_id,
                    instruction,
                    account_keys,
                    status: if failed {
                        InvocationStatus::Failed
                    } else {
                        InvocationStatus::Unknown
                    },
                    error: failed.then(|| ExecutionError {
                        code: "program_failed".to_string(),
                        message: "program failure observed in logs".to_string(),
                    }),
                })
            })
            .collect();
    }

    let mut roots: Vec<InvocationNode> = Vec::new();
    let mut stack: Vec<(u32, Vec<usize>)> = vec![(1, Vec::new())];

    for (position, instruction) in inner.iter().enumerate() {
        let stack_height = instruction
            .get("stackHeight")
            .and_then(Value::as_u64)
            .unwrap_or(2) as u32;
        while stack
            .last()
            .is_some_and(|(height, _)| *height >= stack_height)
        {
            stack.pop();
        }

        let parent_path = stack
            .last()
            .map(|(_, path)| path.clone())
            .unwrap_or_default();
        let id = if parent_path.is_empty() {
            format!("{top_level_id}.{}", roots.len() + 1)
        } else {
            let parent = node_mut_by_path(&mut roots, &parent_path).ok_or_else(|| {
                RpcIngestError::InvalidField {
                    field: "innerInstructions.stackHeight",
                    reason: "parent path disappeared while building CPI tree".to_string(),
                }
            })?;
            format!("{}.{}", parent.id, parent.children.len() + 1)
        };
        let parent_id = if parent_path.is_empty() {
            Some(top_level_id.to_string())
        } else {
            node_mut_by_path(&mut roots, &parent_path).map(|node| node.id.clone())
        };
        let program_id = account_key(account_keys, usize_field(instruction, "programIdIndex")?)?;
        let failed = failed_program_id == Some(program_id.as_str());
        let node = instruction_node(NodeSpec {
            id,
            top_level_instruction: top_level_index,
            parent_id,
            stack_height,
            program_id,
            instruction,
            account_keys,
            status: if failed {
                InvocationStatus::Failed
            } else {
                InvocationStatus::Unknown
            },
            error: failed.then(|| ExecutionError {
                code: "program_failed".to_string(),
                message: "program failure observed in logs".to_string(),
            }),
        })?;

        let current_path = if parent_path.is_empty() {
            roots.push(node);
            vec![roots.len() - 1]
        } else {
            let parent = node_mut_by_path(&mut roots, &parent_path).ok_or_else(|| {
                RpcIngestError::InvalidField {
                    field: "innerInstructions.stackHeight",
                    reason: "parent path disappeared while attaching CPI".to_string(),
                }
            })?;
            parent.children.push(node);
            let mut path = parent_path;
            path.push(parent.children.len() - 1);
            path
        };
        stack.push((stack_height, current_path));

        if position + 1 == inner.len() && failed_program_id.is_some() && !contains_failed(&roots) {
            *quality = worsen(quality.clone(), TraceQuality::Ambiguous);
        }
    }

    Ok(roots)
}

struct NodeSpec<'a> {
    id: String,
    top_level_instruction: usize,
    parent_id: Option<String>,
    stack_height: u32,
    program_id: String,
    instruction: &'a Value,
    account_keys: &'a [String],
    status: InvocationStatus,
    error: Option<ExecutionError>,
}

fn instruction_node(spec: NodeSpec<'_>) -> Result<InvocationNode, RpcIngestError> {
    let account_indices = spec
        .instruction
        .get("accounts")
        .and_then(Value::as_array)
        .map(|accounts| {
            accounts
                .iter()
                .map(|value| {
                    value.as_u64().map(|value| value as usize).ok_or_else(|| {
                        RpcIngestError::InvalidField {
                            field: "instruction.accounts",
                            reason: "account index is not an integer".to_string(),
                        }
                    })
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?
        .unwrap_or_default();
    let account_pubkeys = account_indices
        .iter()
        .filter_map(|index| spec.account_keys.get(*index))
        .cloned()
        .collect();

    Ok(InvocationNode {
        id: spec.id,
        top_level_instruction: spec.top_level_instruction,
        parent_id: spec.parent_id,
        stack_height: spec.stack_height,
        program_id: spec.program_id,
        account_indices,
        account_pubkeys,
        raw_data_base64: spec
            .instruction
            .get("data")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        decoded: None,
        logs: Vec::new(),
        status: spec.status,
        error: spec.error,
        children: Vec::new(),
    })
}

fn group_inner_instructions(inner_groups: &[Value]) -> HashMap<usize, Vec<Value>> {
    let mut grouped = HashMap::new();
    for group in inner_groups {
        let Some(index) = group.get("index").and_then(Value::as_u64) else {
            continue;
        };
        let instructions = group
            .get("instructions")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        grouped.insert(index as usize, instructions);
    }
    grouped
}

fn assign_logs(log_messages: &[String]) -> Vec<ProgramLog> {
    log_messages
        .iter()
        .map(|message| ProgramLog {
            invocation_id: None,
            message: message.clone(),
        })
        .collect()
}

fn failed_instruction_index(err: &Value) -> Option<usize> {
    let array = err.get("InstructionError")?.as_array()?;
    array.first()?.as_u64().map(|value| value as usize)
}

fn failed_program_from_logs(logs: &[String]) -> Option<String> {
    logs.iter().find_map(|line| {
        let rest = line.strip_prefix("Program ")?;
        let (program, suffix) = rest.split_once(' ')?;
        suffix.starts_with("failed:").then(|| program.to_string())
    })
}

fn parse_return_data(value: &Value) -> Option<ReturnData> {
    let program_id = value.get("programId")?.as_str()?.to_string();
    let data_base64 = value
        .get("data")?
        .as_array()?
        .first()?
        .as_str()?
        .to_string();
    Some(ReturnData {
        program_id,
        data_base64,
    })
}

fn parse_transaction_version(value: Option<&Value>) -> TransactionVersion {
    match value {
        Some(Value::String(version)) if version == "legacy" => TransactionVersion::Legacy,
        Some(Value::Number(number)) if number.as_u64() == Some(0) => TransactionVersion::V0,
        Some(Value::Number(number)) if number.as_u64() == Some(1) => TransactionVersion::V1,
        Some(Value::Number(number)) => number
            .as_u64()
            .map(|value| TransactionVersion::Unknown(value as u8))
            .unwrap_or(TransactionVersion::Unknown(u8::MAX)),
        _ => TransactionVersion::Legacy,
    }
}

fn normalize_error(err: &Value) -> ExecutionError {
    ExecutionError {
        code: err
            .as_object()
            .and_then(|object| object.keys().next())
            .cloned()
            .unwrap_or_else(|| "transaction_error".to_string()),
        message: err.to_string(),
    }
}

fn canonical_account_keys(static_keys: &[String], loaded: &LoadedAddresses) -> Vec<String> {
    let mut account_keys = static_keys.to_vec();
    account_keys.extend(loaded.writable.clone());
    account_keys.extend(loaded.readonly.clone());
    account_keys
}

fn account_key(account_keys: &[String], index: usize) -> Result<String, RpcIngestError> {
    account_keys
        .get(index)
        .cloned()
        .ok_or_else(|| RpcIngestError::InvalidField {
            field: "programIdIndex",
            reason: format!("account index {index} out of bounds"),
        })
}

fn usize_field(value: &Value, field: &'static str) -> Result<usize, RpcIngestError> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .map(|value| value as usize)
        .ok_or(RpcIngestError::MissingField(field))
}

fn string_array(value: &Value, field: &'static str) -> Result<Vec<String>, RpcIngestError> {
    value
        .as_array()
        .ok_or_else(|| RpcIngestError::InvalidField {
            field,
            reason: "expected array".to_string(),
        })?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(ToString::to_string)
                .ok_or_else(|| RpcIngestError::InvalidField {
                    field,
                    reason: "expected string entry".to_string(),
                })
        })
        .collect()
}

fn string_array_lossy(values: &[Value]) -> Vec<String> {
    values
        .iter()
        .filter_map(Value::as_str)
        .map(ToString::to_string)
        .collect()
}

fn sha256_json(value: &Value) -> String {
    let bytes = serde_json::to_vec(value).unwrap_or_default();
    let digest = Sha256::digest(bytes);
    format!("sha256:{}", to_hex(&digest))
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn node_mut_by_path<'a>(
    nodes: &'a mut [InvocationNode],
    path: &[usize],
) -> Option<&'a mut InvocationNode> {
    let (first, rest) = path.split_first()?;
    let node = nodes.get_mut(*first)?;
    if rest.is_empty() {
        Some(node)
    } else {
        node_mut_by_path(&mut node.children, rest)
    }
}

fn contains_failed(nodes: &[InvocationNode]) -> bool {
    nodes
        .iter()
        .any(|node| node.status == InvocationStatus::Failed || contains_failed(&node.children))
}

fn worsen(current: TraceQuality, candidate: TraceQuality) -> TraceQuality {
    match (current, candidate) {
        (TraceQuality::Ambiguous, _) | (_, TraceQuality::Ambiguous) => TraceQuality::Ambiguous,
        (TraceQuality::Partial, _) | (_, TraceQuality::Partial) => TraceQuality::Partial,
        _ => TraceQuality::Complete,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load(name: &str) -> TransactionTrace {
        let raw = std::fs::read_to_string(format!("../../fixtures/rpc/{name}.json")).unwrap();
        let response: Value = serde_json::from_str(&raw).unwrap();
        let trace = transaction_trace_from_rpc_response(&response, Some("fallback")).unwrap();
        trace.validate().unwrap();
        trace
    }

    #[test]
    fn successful_legacy_transaction() {
        let trace = load("successful-legacy");
        assert!(trace.success);
        assert_eq!(trace.transaction_version, TransactionVersion::Legacy);
        assert!(trace.accounts[0].is_signer);
        assert!(trace.accounts[0].is_writable);
        assert_eq!(trace.trace_quality, TraceQuality::Complete);
    }

    #[test]
    fn failed_legacy_transaction() {
        let trace = load("failed-legacy");
        assert!(!trace.success);
        assert_eq!(trace.error.as_ref().unwrap().code, "InstructionError");
        assert_eq!(trace.failing_invocation().unwrap().id, "0");
    }

    #[test]
    fn v0_transaction() {
        let trace = load("v0");
        assert_eq!(trace.transaction_version, TransactionVersion::V0);
        assert_eq!(trace.accounts.len(), 3);
    }

    #[test]
    fn v0_transaction_using_alt_loaded_accounts() {
        let trace = load("v0-alt");
        assert_eq!(trace.accounts.len(), 5);
        assert_eq!(
            trace.accounts[3].pubkey,
            "LoadedWritable1111111111111111111111111111"
        );
        assert!(trace.accounts[3].is_writable);
        assert_eq!(
            trace.invocations[0].account_pubkeys[1],
            "LoadedWritable1111111111111111111111111111"
        );
        assert_eq!(trace.address_lookups.len(), 1);
    }

    #[test]
    fn nested_cpi_failure() {
        let trace = load("nested-cpi-failure");
        let failed = trace.failing_invocation().unwrap();
        assert_eq!(failed.id, "0.1.1");
        assert_eq!(
            failed.program_id,
            "NestedFailProgram1111111111111111111111111"
        );
    }

    #[test]
    fn missing_truncated_logs_marks_partial() {
        let trace = load("missing-logs");
        assert_eq!(trace.trace_quality, TraceQuality::Partial);
    }

    #[test]
    fn unknown_program_remains_valid_node() {
        let trace = load("unknown-program");
        assert_eq!(
            trace.invocations[0].program_id,
            "UnknownProgram1111111111111111111111111111"
        );
        assert!(trace.invocations[0].decoded.is_none());
    }

    #[test]
    fn incomplete_metadata_marks_partial() {
        let trace = load("incomplete-metadata");
        assert_eq!(trace.trace_quality, TraceQuality::Partial);
        assert!(trace.compute.units_consumed.is_none());
    }
}
