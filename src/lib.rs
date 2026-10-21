use std::fmt;

pub const MAX_UINT256_HEX: &str =
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Unknown,
}

impl RiskLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Argument {
    pub name: &'static str,
    pub kind: &'static str,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Analysis {
    pub selector: String,
    pub signature: Option<&'static str>,
    pub function: Option<&'static str>,
    pub risk: RiskLevel,
    pub summary: String,
    pub arguments: Vec<Argument>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnalyzeError {
    EmptyInput,
    InvalidHexCharacter(char),
    OddLength,
    TooShort,
    InvalidLength { expected: usize, actual: usize },
    InvalidBoolean,
}

impl fmt::Display for AnalyzeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyInput => write!(f, "calldata is empty"),
            Self::InvalidHexCharacter(ch) => write!(f, "invalid hex character: {ch}"),
            Self::OddLength => write!(f, "hex calldata must contain an even number of digits"),
            Self::TooShort => write!(f, "calldata must contain at least a 4-byte selector"),
            Self::InvalidLength { expected, actual } => write!(
                f,
                "calldata length mismatch: expected {expected} bytes, got {actual}"
            ),
            Self::InvalidBoolean => write!(f, "ABI bool must be encoded as 0 or 1"),
        }
    }
}

impl std::error::Error for AnalyzeError {}

fn hex_nibble(byte: u8) -> Result<u8, AnalyzeError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        other => Err(AnalyzeError::InvalidHexCharacter(other as char)),
    }
}

pub fn decode_hex(input: &str) -> Result<Vec<u8>, AnalyzeError> {
    let trimmed = input.trim();
    let hex = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);

    if hex.is_empty() {
        return Err(AnalyzeError::EmptyInput);
    }

    if hex.len() & 1 != 0 {
        return Err(AnalyzeError::OddLength);
    }

    let bytes = hex.as_bytes();
    let mut output = Vec::with_capacity(bytes.len() / 2);

    for pair in bytes.chunks_exact(2) {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        output.push((high << 4) | low);
    }

    Ok(output)
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);

    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }

    output
}

fn address_from_word(word: &[u8]) -> String {
    format!("0x{}", bytes_to_hex(&word[12..32]))
}

fn bool_from_word(word: &[u8]) -> Result<bool, AnalyzeError> {
    if word[..31].iter().any(|byte| *byte != 0) {
        return Err(AnalyzeError::InvalidBoolean);
    }

    match word[31] {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(AnalyzeError::InvalidBoolean),
    }
}

fn uint256_hex(word: &[u8]) -> String {
    format!("0x{}", bytes_to_hex(word))
}

fn uint256_decimal(word: &[u8]) -> String {
    if word.iter().all(|byte| *byte == 0) {
        return "0".to_string();
    }

    let mut digits = vec![0u8];

    for byte in word {
        let mut carry = *byte as u16;
        for digit in &mut digits {
            let value = (*digit as u16) * 256 + carry;
            *digit = (value % 10) as u8;
            carry = value / 10;
        }

        while carry > 0 {
            digits.push((carry % 10) as u8);
            carry /= 10;
        }
    }

    digits
        .iter()
        .rev()
        .map(|digit| char::from(b'0' + *digit))
        .collect()
}

fn selector_hex(bytes: &[u8]) -> String {
    format!("0x{}", bytes_to_hex(&bytes[..4]))
}

fn expect_len(bytes: &[u8], expected: usize) -> Result<(), AnalyzeError> {
    if bytes.len() == expected {
        Ok(())
    } else {
        Err(AnalyzeError::InvalidLength {
            expected,
            actual: bytes.len(),
        })
    }
}

fn word(bytes: &[u8], index: usize) -> &[u8] {
    let start = 4 + index * 32;
    &bytes[start..start + 32]
}

pub fn analyze_calldata(input: &str) -> Result<Analysis, AnalyzeError> {
    let bytes = decode_hex(input)?;

    if bytes.len() < 4 {
        return Err(AnalyzeError::TooShort);
    }

    let selector = selector_hex(&bytes);
    let selector_bytes = &bytes[..4];

    match selector_bytes {
        [0x09, 0x5e, 0xa7, 0xb3] => analyze_approve(bytes, selector),
        [0xa9, 0x05, 0x9c, 0xbb] => analyze_transfer(bytes, selector),
        [0x23, 0xb8, 0x72, 0xdd] => analyze_transfer_from(bytes, selector),
        [0xa2, 0x2c, 0xb4, 0x65] => analyze_set_approval_for_all(bytes, selector),
        _ => Ok(Analysis {
            selector,
            signature: None,
            function: None,
            risk: RiskLevel::Unknown,
            summary: "Unknown selector; SignLens did not decode this call.".to_string(),
            arguments: Vec::new(),
            warnings: vec![
                "Do not assume an unknown call is safe. Verify it with a trusted ABI before signing."
                    .to_string(),
            ],
        }),
    }
}

fn analyze_approve(bytes: Vec<u8>, selector: String) -> Result<Analysis, AnalyzeError> {
    expect_len(&bytes, 68)?;
    let spender = address_from_word(word(&bytes, 0));
    let amount_word = word(&bytes, 1);
    let amount_hex = uint256_hex(amount_word);
    let amount_decimal = uint256_decimal(amount_word);
    let unlimited = bytes_to_hex(amount_word) == MAX_UINT256_HEX;

    let (risk, summary, warnings) = if unlimited {
        (
            RiskLevel::High,
            "Unlimited ERC-20 approval grants the spender permission to use the full token balance."
                .to_string(),
            vec![
                "Unlimited allowance detected (uint256 max).".to_string(),
                "Verify the spender address and use a limited allowance when possible.".to_string(),
            ],
        )
    } else if amount_word.iter().all(|byte| *byte == 0) {
        (
            RiskLevel::Low,
            "ERC-20 approval sets the spender allowance to zero, commonly used to revoke access."
                .to_string(),
            Vec::new(),
        )
    } else {
        (
            RiskLevel::Medium,
            "ERC-20 approval grants a spender permission to transfer tokens up to the specified amount."
                .to_string(),
            vec!["Verify the spender address and allowance amount before signing.".to_string()],
        )
    };

    Ok(Analysis {
        selector,
        signature: Some("approve(address,uint256)"),
        function: Some("approve"),
        risk,
        summary,
        arguments: vec![
            Argument {
                name: "spender",
                kind: "address",
                value: spender,
            },
            Argument {
                name: "amount",
                kind: "uint256",
                value: amount_decimal,
            },
            Argument {
                name: "amountHex",
                kind: "uint256_hex",
                value: amount_hex,
            },
        ],
        warnings,
    })
}

fn analyze_transfer(bytes: Vec<u8>, selector: String) -> Result<Analysis, AnalyzeError> {
    expect_len(&bytes, 68)?;
    let recipient = address_from_word(word(&bytes, 0));
    let amount_word = word(&bytes, 1);

    Ok(Analysis {
        selector,
        signature: Some("transfer(address,uint256)"),
        function: Some("transfer"),
        risk: RiskLevel::Medium,
        summary: "ERC-20 transfer moves tokens to the specified recipient.".to_string(),
        arguments: vec![
            Argument {
                name: "recipient",
                kind: "address",
                value: recipient,
            },
            Argument {
                name: "amount",
                kind: "uint256",
                value: uint256_decimal(amount_word),
            },
            Argument {
                name: "amountHex",
                kind: "uint256_hex",
                value: uint256_hex(amount_word),
            },
        ],
        warnings: vec!["Verify the recipient and amount before signing.".to_string()],
    })
}

fn analyze_transfer_from(bytes: Vec<u8>, selector: String) -> Result<Analysis, AnalyzeError> {
    expect_len(&bytes, 100)?;
    let sender = address_from_word(word(&bytes, 0));
    let recipient = address_from_word(word(&bytes, 1));
    let amount_word = word(&bytes, 2);

    Ok(Analysis {
        selector,
        signature: Some("transferFrom(address,address,uint256)"),
        function: Some("transferFrom"),
        risk: RiskLevel::Medium,
        summary: "ERC-20 transferFrom moves tokens from one address to another using an allowance."
            .to_string(),
        arguments: vec![
            Argument {
                name: "from",
                kind: "address",
                value: sender,
            },
            Argument {
                name: "to",
                kind: "address",
                value: recipient,
            },
            Argument {
                name: "amount",
                kind: "uint256",
                value: uint256_decimal(amount_word),
            },
            Argument {
                name: "amountHex",
                kind: "uint256_hex",
                value: uint256_hex(amount_word),
            },
        ],
        warnings: vec!["Verify the source, recipient, and amount before signing.".to_string()],
    })
}

fn analyze_set_approval_for_all(
    bytes: Vec<u8>,
    selector: String,
) -> Result<Analysis, AnalyzeError> {
    expect_len(&bytes, 68)?;
    let operator = address_from_word(word(&bytes, 0));
    let approved = bool_from_word(word(&bytes, 1))?;

    let (risk, summary, warnings) = if approved {
        (
            RiskLevel::High,
            "NFT operator approval allows the operator to manage every token in the collection for this owner."
                .to_string(),
            vec![
                "setApprovalForAll(true) detected.".to_string(),
                "Verify the operator address carefully before signing.".to_string(),
            ],
        )
    } else {
        (
            RiskLevel::Low,
            "NFT operator approval is being revoked.".to_string(),
            Vec::new(),
        )
    };

    Ok(Analysis {
        selector,
        signature: Some("setApprovalForAll(address,bool)"),
        function: Some("setApprovalForAll"),
        risk,
        summary,
        arguments: vec![
            Argument {
                name: "operator",
                kind: "address",
                value: operator,
            },
            Argument {
                name: "approved",
                kind: "bool",
                value: approved.to_string(),
            },
        ],
        warnings,
    })
}

fn json_escape(value: &str) -> String {
    let mut output = String::with_capacity(value.len() + 8);

    for ch in value.chars() {
        match ch {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            ch if ch.is_control() => output.push_str(&format!("\\u{:04x}", ch as u32)),
            ch => output.push(ch),
        }
    }

    output
}

fn json_string(value: &str) -> String {
    format!("\"{}\"", json_escape(value))
}

pub fn format_json(analysis: &Analysis) -> String {
    let signature = analysis
        .signature
        .map(json_string)
        .unwrap_or_else(|| "null".to_string());
    let function = analysis
        .function
        .map(json_string)
        .unwrap_or_else(|| "null".to_string());

    let arguments = analysis
        .arguments
        .iter()
        .map(|argument| {
            format!(
                "{{\"name\":{},\"type\":{},\"value\":{}}}",
                json_string(argument.name),
                json_string(argument.kind),
                json_string(&argument.value)
            )
        })
        .collect::<Vec<_>>()
        .join(",");

    let warnings = analysis
        .warnings
        .iter()
        .map(|warning| json_string(warning))
        .collect::<Vec<_>>()
        .join(",");

    let mut output = String::from("{\n");
    output.push_str(&format!(
        "  \"selector\": {},\n",
        json_string(&analysis.selector)
    ));
    output.push_str(&format!("  \"signature\": {signature},\n"));
    output.push_str(&format!("  \"function\": {function},\n"));
    output.push_str(&format!(
        "  \"risk\": {},\n",
        json_string(analysis.risk.as_str())
    ));
    output.push_str(&format!(
        "  \"summary\": {},\n",
        json_string(&analysis.summary)
    ));
    output.push_str(&format!("  \"arguments\": [{arguments}],\n"));
    output.push_str(&format!("  \"warnings\": [{warnings}]\n"));
    output.push('}');
    output
}

pub fn format_human(analysis: &Analysis) -> String {
    let mut lines = vec![
        "SignLens transaction analysis".to_string(),
        format!("Risk:      {}", analysis.risk.as_str()),
        format!("Selector:  {}", analysis.selector),
        format!(
            "Function:  {}",
            analysis.signature.unwrap_or("unknown selector")
        ),
        format!("Summary:   {}", analysis.summary),
    ];

    if !analysis.arguments.is_empty() {
        lines.push(String::new());
        lines.push("Arguments:".to_string());
        for argument in &analysis.arguments {
            lines.push(format!("  {}: {}", argument.name, argument.value));
        }
    }

    if !analysis.warnings.is_empty() {
        lines.push(String::new());
        lines.push("Warnings:".to_string());
        for warning in &analysis.warnings {
            lines.push(format!("  - {warning}"));
        }
    }

    lines.join("\n")
}
