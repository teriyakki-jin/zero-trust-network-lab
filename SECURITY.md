# Security policy

## Scope

This repository is an educational local lab. It demonstrates security architecture concepts but is not a supported production security gateway.

## Reporting a vulnerability

Please do not disclose a suspected vulnerability in a public issue. Use GitHub's private vulnerability reporting or Security Advisory workflow for this repository.

Include the affected component, reproduction steps, expected impact, and any suggested mitigation. Do not include real credentials, tokens, personal information, or data from systems you do not own.

## Safe use

- Keep `.env` out of version control.
- Bind the exposed lab ports to loopback only.
- Do not reuse generated lab passwords.
- Do not expose `start-dev` Keycloak or the OPA API to an untrusted network.
- Replace simulated posture headers before adapting the design to a real environment.
- Use only accounts, devices, and networks you are authorized to test.
