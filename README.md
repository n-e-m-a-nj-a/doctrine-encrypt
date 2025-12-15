# NC Doctrine Encrypt (WORK IN PROGRESS)
Features
- Annotation + PHP 8 Attribute support to mark entity properties encrypted.
- Symmetric (libsodium secretbox) encryptor.
- Hybrid asymmetric encryptor (per-row data key wrapped with owner's public key).
- Deterministic HMAC-SHA256 index for equality-searchable fields.
- Abstract OwnerProvider and OwnerKeyProvider for integrating with your app/KMS/HSM.
- Key-versioning support in payloads and re-encryption/migration helpers.
- Symfony Bundle for easy integration.
- PHPUnit tests and GitHub Actions CI provided.

Security notes
- Deterministic index leaks equality metadata. Use only where acceptable.
- Use a real KMS/HSM in production. StaticOwnerKeyProvider is for testing only.
- For hybrid mode, keep owner private keys strictly controlled.
