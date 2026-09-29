use serde::{Deserialize, Serialize};
use trace::{InvocationNode, ProgramLog, TraceQuality, TransactionTrace};

pub const EVIDENCE_SCHEMA_VERSION: &str = "solana-debug/evidence@0.1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProofGrade {
    Observed,
    RuleMatch,
    Reproduced,
    CausallyVerified,
    UnverifiedHypothesis,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Fact {
    pub id: String,
    pub statement: String,
    pub source: String,
    pub observed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Location {
    pub top_level_instruction: usize,
    pub cpi_path: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SuggestedExperiment {
    pub kind: String,
    pub from: Option<String>,
    pub to: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Finding {
    pub rule_id: String,
    pub severity: Severity,
    pub proof: ProofGrade,
    pub location: Option<Location>,
    pub facts: Vec<Fact>,
    pub suggested_experiment: Option<SuggestedExperiment>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Evidence {
    pub schema: String,
    pub trace_id: String,
    pub transaction_success: bool,
    pub trace_quality: TraceQuality,
    pub deterministic_findings: Vec<Finding>,
    pub raw_account_data_in_prompt: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Report {
    pub transaction: TransactionSummary,
    pub failure: Option<FailureSummary>,
    pub evidence: Evidence,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransactionSummary {
    pub status: String,
    pub version: String,
    pub slot: Option<u64>,
    pub signature: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FailureSummary {
    pub invocation_id: String,
    pub top_level_instruction: usize,
    pub program_id: String,
    pub decoded_instruction: Option<DecodedInstructionSummary>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub accounts: Vec<FailureAccount>,
    pub logs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecodedInstructionSummary {
    pub program: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FailureAccount {
    pub index: usize,
    pub pubkey: String,
    pub is_signer: Option<bool>,
    pub is_writable: Option<bool>,
}

impl Evidence {
    pub fn from_trace(trace: &TransactionTrace, findings: Vec<Finding>) -> Self {
        Self {
            schema: EVIDENCE_SCHEMA_VERSION.to_string(),
            trace_id: trace.wire_sha256.clone(),
            transaction_success: trace.success,
            trace_quality: trace.trace_quality.clone(),
            deterministic_findings: findings,
            raw_account_data_in_prompt: false,
        }
    }
}

impl Report {
    pub fn from_trace(trace: &TransactionTrace, findings: Vec<Finding>) -> Self {
        Self {
            transaction: TransactionSummary {
                status: if trace.success { "succeeded" } else { "failed" }.to_string(),
                version: format!("{:?}", trace.transaction_version),
                slot: trace.slot,
                signature: trace.signature.clone(),
            },
            failure: FailureSummary::from_trace(trace),
            evidence: Evidence::from_trace(trace, findings),
        }
    }
}

impl FailureSummary {
    fn from_trace(trace: &TransactionTrace) -> Option<Self> {
        let failing = trace.failing_invocation()?;
        let logs = failure_logs(failing, &trace.logs);
        let error = failing.error.as_ref().or(trace.error.as_ref());
        Some(Self {
            invocation_id: failing.id.clone(),
            top_level_instruction: failing.top_level_instruction,
            program_id: failing.program_id.clone(),
            decoded_instruction: failing.decoded.as_ref().map(|decoded| {
                DecodedInstructionSummary {
                    program: decoded.program.clone(),
                    name: decoded.name.clone(),
                }
            }),
            error_code: error.map(|error| error.code.clone()),
            error_message: error.map(|error| error.message.clone()),
            accounts: failing
                .account_indices
                .iter()
                .enumerate()
                .map(|(position, index)| {
                    let account = trace
                        .accounts
                        .iter()
                        .find(|account| account.index == *index);
                    FailureAccount {
                        index: *index,
                        pubkey: failing
                            .account_pubkeys
                            .get(position)
                            .cloned()
                            .or_else(|| account.map(|account| account.pubkey.clone()))
                            .unwrap_or_else(|| "<unknown>".to_string()),
                        is_signer: account.map(|account| account.is_signer),
                        is_writable: account.map(|account| account.is_writable),
                    }
                })
                .collect(),
            logs,
        })
    }
}

fn failure_logs(failing: &InvocationNode, transaction_logs: &[ProgramLog]) -> Vec<String> {
    if !failing.logs.is_empty() {
        return failing.logs.clone();
    }

    transaction_logs
        .iter()
        .map(|log| log.message.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_includes_failure_context() {
        let raw = include_str!("../../../fixtures/trace/failing-token-program-mismatch.json");
        let trace: TransactionTrace = serde_json::from_str(raw).unwrap();
        let report = Report::from_trace(&trace, Vec::new());
        let failure = report.failure.unwrap();

        assert_eq!(failure.invocation_id, "2.1");
        assert_eq!(
            failure.program_id,
            "ATokenGPvoter111111111111111111111111111111"
        );
        assert_eq!(failure.accounts.len(), 2);
        assert!(!failure.logs.is_empty());
    }
}
