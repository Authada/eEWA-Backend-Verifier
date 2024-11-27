# EUDI Verifier Backend

Based on the EU reference implementation with commit 1ba6ccc186fb2f1b8c9beeb119142def1c71121e

See https://github.com/eu-digital-identity-wallet/eudi-srv-web-verifier-endpoint-23220-4-kt/commit/1ba6ccc186fb2f1b8c9beeb119142def1c71121e

# Fixes added for conformance test
- Add support for x5c header in sd-jwt signature validation

# Changes made in phase 2:
- Add verifier attestation
- Add support for multiple credentials in result
- Allow overriding clientid scheme and clientid from presentation request creation

# Changes made in phase 1:
- Added signature and authenticated channel checks for credentials in credential response validation
