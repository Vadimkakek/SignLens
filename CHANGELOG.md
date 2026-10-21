# Changelog

## 0.1.0

Initial public release of SignLens.

### Added

- offline decoding for common ERC-20 and NFT approval calldata
- ERC-20 `approve`, `transfer`, and `transferFrom` analysis
- NFT `setApprovalForAll` analysis
- high-risk detection for unlimited ERC-20 approvals
- high-risk detection for global NFT operator approvals
- human-readable and JSON output
- deterministic exit codes for scripts and CI
- zero runtime dependencies
- Rust tests and GitHub Actions CI
