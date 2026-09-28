# Security Policy

## Supported versions

Security fixes are provided for the latest released version of klahack-portscope.

| Version | Supported |
|---|---|
| 1.0.x | Yes |
| Earlier versions | No |

## Reporting a vulnerability privately

Please do not open a public issue for an unpatched vulnerability.

1. Open the repository's **Security** tab on GitHub.
2. Select **Advisories**.
3. Select **Report a vulnerability** to create a private security advisory.
4. Include the affected version, operating system, reproduction steps, impact, and any proposed mitigation.

GitHub's private security advisory keeps the report and follow-up discussion private while the issue is investigated. Please avoid including secrets, personal data, or scan results from systems you do not own.

## Scope

Useful reports include command injection, unsafe installer behavior, checksum verification bypasses, terminal injection bypasses, authorization-gate bypasses, unintended external network access, and denial-of-service conditions caused by valid input.

General feature requests, support questions, and reports without a security impact belong in regular GitHub issues.

## Responsible testing

Test suspected issues only against systems you own or have explicit written permission to assess. The automated test suite intentionally binds only to loopback.
