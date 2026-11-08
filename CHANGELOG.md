# Changelog

## 1.1.0

### Added

- Add an SSH key to a host's authorized_keys through Termix actions, so one key can go to many hosts in a rollout
- The assistant and MCP can list your SSH key names

### Changed

- Needs Termix 26.11.1 or newer

## 1.0.0

### Added

- Generate Ed25519, ECDSA and RSA key pairs in the credential editor
- Get the public key from a private key, detect key types and check that a key pair matches
- Deploy a key credential's public key to a host's authorized keys, written to the audit log
