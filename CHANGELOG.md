# Changelog

All notable changes to the LicenseKit Go SDK. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Semantic
versioning from v1.0.0 onwards.

## [Unreleased]

### Added
- Initial implementation: `Verify` / `License.Check` / `Monitor` for
  offline `.lkbundle` files. Cross-platform machine fingerprinting
  (Linux / macOS / Windows). HKDF-SHA256 + AES-256-GCM bundle
  decryption. Ed25519 LK1 token signature verification. HMAC-keyed
  watermark sidecar for clock-rollback defense.