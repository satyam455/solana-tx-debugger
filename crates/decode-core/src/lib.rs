use serde::Deserialize;
use std::{collections::BTreeMap, fs, path::Path};
use trace::{DecodedInstruction, ExecutionError, InvocationNode, TraceValue, TransactionTrace};

const SYSTEM_PROGRAM: &str = "11111111111111111111111111111111";
const COMPUTE_BUDGET_PROGRAM: &str = "ComputeBudget111111111111111111111111111111";
const SPL_TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const TOKEN_2022_PROGRAM: &str = "TokenzQdBNbLqP5VEhdkAS6EPFq6qvKxExzS1S1S1S";
const ASSOCIATED_TOKEN_PROGRAM: &str = "ATokenGPvoter111111111111111111111111111111";

#[derive(Debug, Default, Clone)]
pub struct DecodeRegistry {
    anchor_errors: BTreeMap<u64, AnchorErrorDef>,
}

#[derive(Debug, Clone)]
struct AnchorErrorDef {
    name: String,
    msg: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AnchorLogError {
    code: u64,
    name: String,
    message: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AnchorIdl {
    errors: Option<Vec<AnchorIdlError>>,
}

#[derive(Debug, Deserialize)]
struct AnchorIdlError {
    code: u64,
    name: String,
    msg: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeSummary {
    pub decoded_invocations: usize,
    pub decoded_errors: usize,
}

impl DecodeRegistry {
    pub fn load_anchor_idl_path(path: &Path) -> Result<Self, DecodeRegistryError> {
        let raw = fs::read_to_string(path)?;
        Self::from_anchor_idl_json(&raw)
    }

    pub fn from_anchor_idl_json(raw: &str) -> Result<Self, DecodeRegistryError> {
        let idl: AnchorIdl = serde_json::from_str(raw)?;
        let mut registry = Self::default();
        for error in idl.errors.unwrap_or_default() {
            registry.anchor_errors.insert(
                error.code,
                AnchorErrorDef {
                    name: error.name,
                    msg: error.msg,
                },
            );
        }
        Ok(registry)
    }

    fn anchor_error(&self, code: u64) -> Option<&AnchorErrorDef> {
        self.anchor_errors.get(&code)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DecodeRegistryError {
    #[error("failed to read IDL: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to parse IDL: {0}")]
    Json(#[from] serde_json::Error),
}

pub fn decode_trace(trace: &mut TransactionTrace, registry: &DecodeRegistry) -> DecodeSummary {
    let mut summary = DecodeSummary {
        decoded_invocations: 0,
        decoded_errors: 0,
    };

    let all_logs = trace
        .logs
        .iter()
        .map(|log| log.message.clone())
        .collect::<Vec<_>>();

    for invocation in &mut trace.invocations {
        decode_invocation(invocation, &all_logs, registry, &mut summary);
    }

    if let Some(error) = &mut trace.error {
        if enrich_error(error, &all_logs, registry) {
            summary.decoded_errors += 1;
        }
    }

    summary
}

fn decode_invocation(
    invocation: &mut InvocationNode,
    all_logs: &[String],
    registry: &DecodeRegistry,
    summary: &mut DecodeSummary,
) {
    if let Some(decoded) = decode_instruction(invocation) {
        invocation.decoded = Some(decoded);
        summary.decoded_invocations += 1;
    }

    if let Some(error) = &mut invocation.error {
        let logs = if invocation.logs.is_empty() {
            all_logs
        } else {
            &invocation.logs
        };
        if enrich_error(error, logs, registry) {
            summary.decoded_errors += 1;
        }
    }

    for child in &mut invocation.children {
        decode_invocation(child, all_logs, registry, summary);
    }
}

fn decode_instruction(invocation: &InvocationNode) -> Option<DecodedInstruction> {
    let data = decode_instruction_data(&invocation.raw_data_base64).unwrap_or_default();
    match invocation.program_id.as_str() {
        SYSTEM_PROGRAM => Some(decoded(
            "system",
            system_instruction_name(&data),
            details(&[]),
        )),
        COMPUTE_BUDGET_PROGRAM => Some(decoded(
            "compute_budget",
            compute_budget_instruction_name(&data),
            details(&[]),
        )),
        SPL_TOKEN_PROGRAM => Some(decoded(
            "spl_token",
            token_instruction_name(&data),
            details(&[("token_program", "legacy")]),
        )),
        TOKEN_2022_PROGRAM => Some(decoded(
            "spl_token_2022",
            token_instruction_name(&data),
            details(&[("token_program", "token_2022")]),
        )),
        ASSOCIATED_TOKEN_PROGRAM => Some(decoded(
            "associated_token",
            associated_token_instruction_name(&data),
            details(&[]),
        )),
        _ => None,
    }
}

fn enrich_error(error: &mut ExecutionError, logs: &[String], registry: &DecodeRegistry) -> bool {
    if let Some(anchor_log_error) = parse_anchor_log_error(logs) {
        error.code = format!("ANCHOR_{}", anchor_log_error.name);
        error.message = match anchor_log_error.message {
            Some(message) => format!(
                "Anchor error {} ({}): {}",
                anchor_log_error.code, anchor_log_error.name, message
            ),
            None => format!(
                "Anchor error {} ({})",
                anchor_log_error.code, anchor_log_error.name
            ),
        };
        return true;
    }

    let Some(anchor) =
        parse_anchor_error_number_from_logs(logs).or_else(|| parse_custom_error(&error.message))
    else {
        return false;
    };

    let mut message = format!("Anchor/custom error {}", anchor);
    if let Some(definition) = registry.anchor_error(anchor) {
        message = match &definition.msg {
            Some(msg) => format!("Anchor error {} ({}): {}", anchor, definition.name, msg),
            None => format!("Anchor error {} ({})", anchor, definition.name),
        };
        error.code = format!("ANCHOR_{}", definition.name);
    } else {
        error.code = format!("CUSTOM_{}", anchor);
    }
    error.message = message;
    true
}

fn parse_anchor_log_error(logs: &[String]) -> Option<AnchorLogError> {
    logs.iter().find_map(|log| {
        let name = value_between(log, "Error Code: ", ". Error Number: ")?;
        let code = value_between(log, "Error Number: ", ". Error Message: ")?
            .parse()
            .ok()?;
        let message = value_after(log, "Error Message: ")
            .map(|message| message.trim_end_matches('.').to_string());
        Some(AnchorLogError {
            code,
            name: name.to_string(),
            message,
        })
    })
}

fn value_between<'a>(value: &'a str, start: &str, end: &str) -> Option<&'a str> {
    let (_, rest) = value.split_once(start)?;
    let (matched, _) = rest.split_once(end)?;
    Some(matched.trim())
}

fn value_after<'a>(value: &'a str, start: &str) -> Option<&'a str> {
    let (_, rest) = value.split_once(start)?;
    Some(rest.trim())
}

fn parse_anchor_error_number_from_logs(logs: &[String]) -> Option<u64> {
    logs.iter().find_map(|log| {
        log.split("Error Number: ")
            .nth(1)
            .and_then(|rest| rest.split(['.', ' ']).next())
            .and_then(|number| number.parse().ok())
    })
}

fn decoded(program: &str, name: &str, details: TraceValue) -> DecodedInstruction {
    DecodedInstruction {
        program: program.to_string(),
        name: name.to_string(),
        details,
    }
}

fn details(entries: &[(&str, &str)]) -> TraceValue {
    TraceValue::Object(
        entries
            .iter()
            .map(|(key, value)| ((*key).to_string(), TraceValue::String((*value).to_string())))
            .collect(),
    )
}

fn decode_instruction_data(data: &str) -> Option<Vec<u8>> {
    if data.is_empty() {
        return Some(Vec::new());
    }
    bs58::decode(data).into_vec().ok()
}

fn system_instruction_name(data: &[u8]) -> &'static str {
    match read_u32_le(data) {
        Some(0) => "create_account",
        Some(1) => "assign",
        Some(2) => "transfer",
        Some(3) => "create_account_with_seed",
        Some(4) => "advance_nonce_account",
        Some(5) => "withdraw_nonce_account",
        Some(6) => "initialize_nonce_account",
        Some(7) => "authorize_nonce_account",
        Some(8) => "allocate",
        Some(9) => "allocate_with_seed",
        Some(10) => "assign_with_seed",
        Some(11) => "transfer_with_seed",
        _ => "unknown",
    }
}

fn compute_budget_instruction_name(data: &[u8]) -> &'static str {
    match data.first().copied() {
        Some(0) => "request_units_deprecated",
        Some(1) => "request_heap_frame",
        Some(2) => "set_compute_unit_limit",
        Some(3) => "set_compute_unit_price",
        Some(4) => "set_loaded_accounts_data_size_limit",
        _ => "unknown",
    }
}

fn token_instruction_name(data: &[u8]) -> &'static str {
    match data.first().copied() {
        Some(0) => "initialize_mint",
        Some(1) => "initialize_account",
        Some(2) => "initialize_multisig",
        Some(3) => "transfer",
        Some(4) => "approve",
        Some(5) => "revoke",
        Some(6) => "set_authority",
        Some(7) => "mint_to",
        Some(8) => "burn",
        Some(9) => "close_account",
        Some(10) => "freeze_account",
        Some(11) => "thaw_account",
        Some(12) => "transfer_checked",
        Some(13) => "approve_checked",
        Some(14) => "mint_to_checked",
        Some(15) => "burn_checked",
        Some(16) => "initialize_account_2",
        Some(17) => "sync_native",
        Some(18) => "initialize_account_3",
        Some(19) => "initialize_multisig_2",
        Some(20) => "initialize_mint_2",
        Some(21) => "get_account_data_size",
        Some(22) => "initialize_immutable_owner",
        Some(23) => "amount_to_ui_amount",
        Some(24) => "ui_amount_to_amount",
        _ => "unknown",
    }
}

fn associated_token_instruction_name(data: &[u8]) -> &'static str {
    match data.first().copied() {
        None => "create",
        Some(0) => "create",
        Some(1) => "create_idempotent",
        Some(2) => "recover_nested",
        _ => "unknown",
    }
}

fn read_u32_le(data: &[u8]) -> Option<u32> {
    let bytes = data.get(0..4)?;
    Some(u32::from_le_bytes(bytes.try_into().ok()?))
}

fn parse_custom_error(message: &str) -> Option<u64> {
    let (_, hex) = message.rsplit_once("0x")?;
    let hex_digits = hex
        .chars()
        .take_while(|ch| ch.is_ascii_hexdigit())
        .collect::<String>();
    u64::from_str_radix(&hex_digits, 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_spl_token_transfer_name() {
        let mut invocation = InvocationNode {
            id: "0".to_string(),
            top_level_instruction: 0,
            parent_id: None,
            stack_height: 1,
            program_id: SPL_TOKEN_PROGRAM.to_string(),
            account_indices: vec![],
            account_pubkeys: vec![],
            raw_data_base64: bs58::encode([3_u8]).into_string(),
            decoded: None,
            logs: vec![],
            status: trace::InvocationStatus::Succeeded,
            error: None,
            children: vec![],
        };

        decode_invocation(
            &mut invocation,
            &[],
            &DecodeRegistry::default(),
            &mut DecodeSummary {
                decoded_invocations: 0,
                decoded_errors: 0,
            },
        );

        assert_eq!(invocation.decoded.unwrap().name, "transfer");
    }

    #[test]
    fn decodes_anchor_error_with_idl_name() {
        let registry = DecodeRegistry::from_anchor_idl_json(
            r#"{"version":"0.1.0","name":"x","errors":[{"code":6001,"name":"ConstraintSeeds","msg":"bad seeds"}]}"#,
        )
        .unwrap();
        let mut error = ExecutionError {
            code: "InstructionError".to_string(),
            message: "custom program error: 0x1771".to_string(),
        };

        assert!(enrich_error(&mut error, &[], &registry));
        assert_eq!(error.code, "ANCHOR_ConstraintSeeds");
        assert!(error.message.contains("bad seeds"));
    }

    #[test]
    fn decodes_structured_anchor_error_log_without_idl() {
        let mut error = ExecutionError {
            code: "InstructionError".to_string(),
            message: "custom program error: 0x1770".to_string(),
        };
        let logs = vec![
            "Program log: Instruction: ValidateNonce".to_string(),
            "Program log: AnchorError thrown in programs/terminal-proxy/src/instructions/validate_nonce.rs:34. Error Code: NonceAlreadyExists. Error Number: 6000. Error Message: Nonce already exists.".to_string(),
        ];

        assert!(enrich_error(&mut error, &logs, &DecodeRegistry::default()));
        assert_eq!(error.code, "ANCHOR_NonceAlreadyExists");
        assert_eq!(
            error.message,
            "Anchor error 6000 (NonceAlreadyExists): Nonce already exists"
        );
    }
}
