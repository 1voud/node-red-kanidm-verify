# node-red-kanidm-verify
A Node-RED node to verify JWTs from <a href="https://kanidm.com/">Kanidm</a>.

This node uses the ES256 algorithm to verify the signature of the token.
It fetches the JWKS from the configured Kanidm instance (inferred from the Info URL or provided directly if the Info URL points to JWKS).

Supports:

  - ES256 Verification
  - Audience check
  - OIDC Discovery (Auto-resolves JWKS URI)
  - Bearer Token extraction from `Authorization` header

## Notes:
  This node is built on top of <a href="https://github.com/panva/jose">jose</a>, a robust library for JWT/JOSE.

## Samples:
### Messages
Input message (Bearer token in header):

    {
        "req": {
            "headers": {
                "authorization": "Bearer <your_jwt_token>"
            }
        }
    }

### Outputs
**Success Output (1)**:
The payload of the verified token.

    "msg.token": {
        "iss": "https://idm.example.com/oauth2/openid/client_id",
        "aud": "audience",
        "exp": 1678900000,
        ...
    }


**Failure Output (2)**:
Error details if verification fails.

    "msg.error": {
        "message": "JWT Verification failed: signature verification failed",
        "code": "VERIFICATION_FAILED"
    }

## Configuration
- **Info URL**: The URL to your Kanidm OIDC discovery endpoint (e.g., `https://idm.example.com/oauth2/openid/client_id/.well-known/openid-configuration`) or directly to the JWKS URL.
- **Audience**: The expected audience (`aud` claim) in the JWT.

Releases:
- v1.0.0 - Initial release
    - ES256 Verification
    - Dual outputs for Success/Failure
