## Upgrade & Key Rotation Guide This document explains steps to rotate keys or migrate between encryptors.

- Prepare new keys in your new KeyProvider or KMS.
- Wire a new encryptor service (for instance 'hybrid' or 'symmetric_v2') that uses the new keys.
- Use the migrate command to re-encrypt rows: php bin/console nc:encrypt:migrate-keys 'App\\Entity\\Note' secret --from=symmetric --to=symmetric_v2 --index
- Verify data and indexes.
- Remove old keys after verifying. Notes: - For large datasets process rows in batches using a bespoke job (this package's ReencryptService is intentionally simple). - Consider including key identifier (kid) in payloads (this code does include kid support).
