# Design and threat model

## Objective

Prevent a valid network connection or a stolen password from becoming broad access to internal resources. The protected application is reachable only through a PEP that verifies identity and requests a decision from OPA for every access attempt.

## Protected assets

| Asset | Primary requirement |
|---|---|
| User and administrator identities | Short-lived tokens, explicit roles, strong authentication |
| Protected application | No direct host exposure; access only through the PEP |
| Policy decision service | Default deny and deterministic policy-as-code |
| Decision logs | No bearer tokens; request-level correlation through UUIDs |

## Threats and controls

| Threat | Lab control |
|---|---|
| Stolen password or token misuse | JWT validation, short token lifetime, audience and issuer checks |
| Unmanaged or unhealthy endpoint | Device posture policy input and default deny |
| Over-privileged employee | Explicit developer/admin role requirement |
| Access to an unintended route | Explicit `/project` resource policy |
| Risky sign-in or session | Risk threshold policy |
| Direct access to the application | Internal-only Docker data-plane network |
| Policy or identity service failure | PEP fails closed with `503` |
| Credential leakage in source control | Generated gitignored `.env`; no committed usable passwords |

## Trust boundaries

1. **User to PEP:** The bearer token is untrusted until signature and claims validation succeeds.
2. **PEP to Keycloak:** The PEP obtains signing keys from an internal JWKS endpoint while enforcing the external issuer claim.
3. **PEP to OPA:** The PEP submits normalized identity, posture, risk, method, and path attributes.
4. **PEP to protected application:** Only allowed requests cross the internal data plane. The token is not forwarded.
5. **Logs:** Structured events include a request ID and decision reason but exclude credentials and tokens.

## Policy decision

The PEP queries `data.zerotrust.access.decision`. The returned object includes:

```json
{
  "allow": true,
  "reason": "allow",
  "session_ttl_seconds": 3600
}
```

If OPA returns an invalid shape, becomes unavailable, or times out, the PEP denies access.

## Production evolution

The next iteration should replace simulated posture with signed device state, use Authorization Code with PKCE and WebAuthn, terminate TLS at a hardened ingress, authenticate service-to-service calls with workload identities, and export signed decision logs to a protected SIEM.
