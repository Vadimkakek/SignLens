use signlens::{analyze_calldata, decode_hex, format_json, RiskLevel};

fn word_address(byte: &str) -> String {
    format!("{}{}", "0".repeat(24), byte.repeat(40))
}

fn word_uint(value: u8) -> String {
    format!("{}{:02x}", "0".repeat(62), value)
}

#[test]
fn decodes_hex_with_optional_prefix() {
    assert_eq!(
        decode_hex("0x095ea7b3").unwrap(),
        vec![0x09, 0x5e, 0xa7, 0xb3]
    );
    assert_eq!(
        decode_hex("095ea7b3").unwrap(),
        vec![0x09, 0x5e, 0xa7, 0xb3]
    );
}

#[test]
fn detects_unlimited_erc20_approval_as_high_risk() {
    let calldata = format!("0x095ea7b3{}{}", word_address("1"), "ff".repeat(32));

    let analysis = analyze_calldata(&calldata).unwrap();
    assert_eq!(analysis.function, Some("approve"));
    assert_eq!(analysis.risk, RiskLevel::High);
    assert!(analysis.summary.contains("Unlimited ERC-20 approval"));
    assert_eq!(
        analysis.arguments[0].value,
        "0x1111111111111111111111111111111111111111"
    );
    assert_eq!(
        analysis.arguments[1].value,
        "115792089237316195423570985008687907853269984665640564039457584007913129639935"
    );
}

#[test]
fn treats_zero_approval_as_low_risk_revoke() {
    let calldata = format!("0x095ea7b3{}{}", word_address("2"), "00".repeat(32));

    let analysis = analyze_calldata(&calldata).unwrap();
    assert_eq!(analysis.risk, RiskLevel::Low);
    assert!(analysis.summary.contains("zero"));
}

#[test]
fn decodes_transfer_amount_in_decimal() {
    let calldata = format!("0xa9059cbb{}{}", word_address("3"), word_uint(42));

    let analysis = analyze_calldata(&calldata).unwrap();
    assert_eq!(analysis.function, Some("transfer"));
    assert_eq!(analysis.risk, RiskLevel::Medium);
    assert_eq!(analysis.arguments[1].value, "42");
}

#[test]
fn decodes_transfer_from() {
    let calldata = format!(
        "0x23b872dd{}{}{}",
        word_address("4"),
        word_address("5"),
        word_uint(7)
    );

    let analysis = analyze_calldata(&calldata).unwrap();
    assert_eq!(analysis.function, Some("transferFrom"));
    assert_eq!(analysis.arguments[2].value, "7");
}

#[test]
fn detects_set_approval_for_all_true_as_high_risk() {
    let calldata = format!("0xa22cb465{}{}", word_address("6"), word_uint(1));

    let analysis = analyze_calldata(&calldata).unwrap();
    assert_eq!(analysis.function, Some("setApprovalForAll"));
    assert_eq!(analysis.risk, RiskLevel::High);
    assert_eq!(analysis.arguments[1].value, "true");
}

#[test]
fn rejects_non_canonical_boolean() {
    let calldata = format!("0xa22cb465{}{}", word_address("7"), word_uint(2));

    assert!(analyze_calldata(&calldata).is_err());
}

#[test]
fn treats_set_approval_for_all_false_as_low_risk() {
    let calldata = format!("0xa22cb465{}{}", word_address("7"), word_uint(0));

    let analysis = analyze_calldata(&calldata).unwrap();
    assert_eq!(analysis.risk, RiskLevel::Low);
    assert_eq!(analysis.arguments[1].value, "false");
}

#[test]
fn unknown_selector_is_reported_without_guessing() {
    let analysis = analyze_calldata("0xdeadbeef").unwrap();
    assert_eq!(analysis.risk, RiskLevel::Unknown);
    assert_eq!(analysis.signature, None);
    assert!(analysis.warnings[0].contains("trusted ABI"));
}

#[test]
fn rejects_short_or_malformed_calldata() {
    assert!(analyze_calldata("0x12").is_err());
    assert!(analyze_calldata("0xxyz1").is_err());
}

#[test]
fn rejects_wrong_argument_length_for_known_selector() {
    let error = analyze_calldata("0xa9059cbb").unwrap_err();
    assert!(error.to_string().contains("length mismatch"));
}

#[test]
fn json_output_is_structured_and_escaped() {
    let calldata = format!("0x095ea7b3{}{}", word_address("8"), word_uint(9));
    let analysis = analyze_calldata(&calldata).unwrap();
    let json = format_json(&analysis);

    assert!(json.contains("\"risk\": \"MEDIUM\""));
    assert!(json.contains("\"function\": \"approve\""));
    assert!(json.contains("\"spender\""));
}
