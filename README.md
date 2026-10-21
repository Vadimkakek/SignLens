# SignLens

SignLens is a small, zero-dependency Rust CLI for inspecting common EVM
transaction calldata before signing it.

It works entirely offline. You paste transaction calldata and SignLens explains
recognized calls, decodes important arguments, and highlights risky approval
patterns.

## Why

Wallet confirmation screens and raw calldata can be hard to reason about.
SignLens focuses on a small set of common token actions where a mistake can be
costly:

- `approve(address,uint256)`
- `transfer(address,uint256)`
- `transferFrom(address,address,uint256)`
- `setApprovalForAll(address,bool)`

The first release intentionally stays small and deterministic instead of
pretending to understand arbitrary contracts without an ABI.

## Safety model

SignLens never needs:

- a private key
- a seed or recovery phrase
- a wallet connection
- an RPC endpoint
- an API key
- an account login

Only transaction calldata is required. The CLI does not make network requests.

Unknown selectors are reported as unknown instead of being guessed.

## Requirements

- Rust stable toolchain

## Build

```bash
git clone https://github.com/Vadimkakek/SignLens.git
cd SignLens
cargo build --release
```

The binary will be available at `target/release/signlens`.

## Usage

```text
signlens <calldata> [--json]
```

Example: a deliberately synthetic unlimited ERC-20 approval using a dummy
address:

```bash
signlens 0x095ea7b30000000000000000000000001111111111111111111111111111111111111111ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
```

Example output:

```text
SignLens transaction analysis
Risk:      HIGH
Selector:  0x095ea7b3
Function:  approve(address,uint256)
Summary:   Unlimited ERC-20 approval grants the spender permission to use the full token balance.

Arguments:
  spender: 0x1111111111111111111111111111111111111111
  amount: 115792089237316195423570985008687907853269984665640564039457584007913129639935
  amountHex: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff

Warnings:
  - Unlimited allowance detected (uint256 max).
  - Verify the spender address and use a limited allowance when possible.
```

The address above is a dummy test value, not a real user wallet.

## JSON output

```bash
signlens <calldata> --json
```

JSON output includes the selector, recognized signature, risk level, decoded
arguments, summary, and warnings.

## Risk levels

- `LOW` — commonly reduces or revokes permissions
- `MEDIUM` — moves assets or grants a bounded allowance
- `HIGH` — broad token permissions such as unlimited approval or
  `setApprovalForAll(true)`
- `UNKNOWN` — SignLens does not recognize the selector and refuses to guess

A risk label is not a guarantee that a transaction is safe. Contract behavior
can depend on code and context that is not visible from calldata alone.

## Exit codes

- `0` — decoded call without a `HIGH` warning
- `1` — invalid arguments or malformed calldata
- `2` — `HIGH`-risk pattern detected
- `3` — unknown selector

## Development

```bash
cargo fmt -- --check
cargo clippy --all-targets -- -D warnings
cargo test
```

The repository intentionally uses no Rust crate dependencies in v0.1.0.

## Privacy

All committed examples use synthetic data only. Do not commit or submit your
wallet secrets, seed phrase, private keys, RPC credentials, or API keys.

See [SECURITY.md](./SECURITY.md).

## Roadmap

- EIP-2612 `permit` decoding
- Permit2 approval decoding
- ERC-721 `safeTransferFrom` decoding
- ABI-assisted decoding for arbitrary calls
- typed-data / EIP-712 inspection
- optional transaction destination context

## License

MIT
