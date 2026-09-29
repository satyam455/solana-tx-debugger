use evidence::{Fact, Finding, Location, ProofGrade, Severity, SuggestedExperiment};
use trace::{InvocationStatus, TransactionTrace};

pub fn analyze(trace: &TransactionTrace) -> Vec<Finding> {
    let mut findings = Vec::new();

    if let Some(finding) = token_program_mismatch(trace) {
        findings.push(finding);
    }
    if let Some(finding) = decoded_anchor_or_custom_error(trace) {
        findings.push(finding);
    }

    if !trace.success && findings.is_empty() {
        findings.push(generic_custom_error(trace));
    }

    findings
}

fn decoded_anchor_or_custom_error(trace: &TransactionTrace) -> Option<Finding> {
    if trace.success {
        return None;
    }
    let failing = trace.failing_invocation()?;
    let error = failing
        .error
        .as_ref()
        .filter(|error| error.code.starts_with("ANCHOR_") || error.code.starts_with("CUSTOM_"))
        .or_else(|| {
            trace.error.as_ref().filter(|error| {
                error.code.starts_with("ANCHOR_") || error.code.starts_with("CUSTOM_")
            })
        })?;
    let is_decoded = error.code.starts_with("ANCHOR_") || error.code.starts_with("CUSTOM_");
    if !is_decoded {
        return None;
    }

    Some(Finding {
        rule_id: if error.code.starts_with("ANCHOR_") {
            "ANCHOR_OR_CUSTOM_ERROR_DECODED".to_string()
        } else {
            "CUSTOM_PROGRAM_ERROR_DECODED".to_string()
        },
        severity: Severity::Error,
        proof: ProofGrade::Observed,
        location: Some(Location {
            top_level_instruction: failing.top_level_instruction,
            cpi_path: vec![failing.id.clone()],
        }),
        facts: vec![
            Fact {
                id: "F1".to_string(),
                statement: format!("Decoded error code: {}", error.code),
                source: format!("invocation:{}", failing.id),
                observed: true,
            },
            Fact {
                id: "F2".to_string(),
                statement: error.message.clone(),
                source: "logs/error".to_string(),
                observed: true,
            },
        ],
        suggested_experiment: None,
    })
}

fn token_program_mismatch(trace: &TransactionTrace) -> Option<Finding> {
    let failing = trace.failing_invocation()?;
    let mentions_token_2022_owner = trace.accounts.iter().any(|account| {
        account
            .owner
            .as_deref()
            .is_some_and(|owner| owner == "TokenzQdBNbLqP5VEhdkAS6EPFq6qvKxExzS1S1S1S")
    });
    let supplied_legacy_token = failing
        .account_pubkeys
        .iter()
        .any(|pubkey| pubkey == "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");

    if !(mentions_token_2022_owner && supplied_legacy_token) {
        return None;
    }

    Some(Finding {
        rule_id: "TOKEN_PROGRAM_MISMATCH".to_string(),
        severity: Severity::Error,
        proof: ProofGrade::RuleMatch,
        location: Some(Location {
            top_level_instruction: failing.top_level_instruction,
            cpi_path: vec![failing.id.clone()],
        }),
        facts: vec![
            Fact {
                id: "F1".to_string(),
                statement: "At least one involved token account is owned by Token-2022".to_string(),
                source: "trace.accounts".to_string(),
                observed: true,
            },
            Fact {
                id: "F2".to_string(),
                statement: "The failing invocation supplied the legacy SPL Token program"
                    .to_string(),
                source: format!("invocation:{}", failing.id),
                observed: true,
            },
            Fact {
                id: "F3".to_string(),
                statement: "The failure occurred in the marked CPI invocation".to_string(),
                source: format!("invocation:{}", failing.id),
                observed: failing.status == InvocationStatus::Failed,
            },
        ],
        suggested_experiment: Some(SuggestedExperiment {
            kind: "replace_program_account".to_string(),
            from: Some("legacy_token".to_string()),
            to: Some("token_2022".to_string()),
        }),
    })
}

fn generic_custom_error(trace: &TransactionTrace) -> Finding {
    let failing = trace.failing_invocation();
    Finding {
        rule_id: "CUSTOM_PROGRAM_ERROR".to_string(),
        severity: Severity::Error,
        proof: ProofGrade::Observed,
        location: failing.map(|node| Location {
            top_level_instruction: node.top_level_instruction,
            cpi_path: vec![node.id.clone()],
        }),
        facts: vec![Fact {
            id: "F1".to_string(),
            statement: "Transaction failed, but no specialized deterministic rule matched"
                .to_string(),
            source: "trace.error".to_string(),
            observed: trace.error.is_some(),
        }],
        suggested_experiment: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_token_program_mismatch_fixture() {
        let raw = include_str!("../../../fixtures/trace/failing-token-program-mismatch.json");
        let trace: TransactionTrace = serde_json::from_str(raw).unwrap();
        let findings = analyze(&trace);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "TOKEN_PROGRAM_MISMATCH");
        assert_eq!(findings[0].proof, ProofGrade::RuleMatch);
    }
}
