# Security Policy

## Reporting a Vulnerability

**Do not report security vulnerabilities through public GitHub issues.**

Email **security@qbitel.dev** with:

- Description of the vulnerability
- Steps to reproduce
- Affected crate(s)
- Potential impact

We will acknowledge receipt within **48 hours** and provide an initial assessment within **5 business days**.

## Scope

| Component | In Scope |
|-----------|----------|
| q-crypto | Crypto implementation flaws, side-channel leaks, KAT failures |
| q-boot | Secure boot bypass, signature verification flaws, rollback circumvention |
| q-kernel | Privilege escalation, memory safety violations, IPC flaws |
| q-identity | Identity spoofing, hardware binding bypass |
| q-attest | Attestation forgery, evidence tampering |
| q-update | Update mechanism bypass, downgrade attacks |
| q-recover | Threshold scheme weaknesses, key recovery flaws |
| q-mesh | Protocol vulnerabilities, session hijacking |
| q-hal | Hardware abstraction security boundaries |
| Tools | Provisioning and signing tool vulnerabilities |

## Out of Scope

- Third-party dependency vulnerabilities (report upstream; notify us if it affects Qbitel EdgeOS)
- DoS through resource exhaustion on the host build system

## Disclosure Timeline

- **Day 0:** Report acknowledged
- **Day 1-5:** Triage and severity assessment (CVSS v3.1)
- **Day 5-30:** Fix developed and tested
- **Day 30-90:** Coordinated disclosure

Critical vulnerabilities (CVSS >= 9.0): patch target within **7 days**.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x | Yes |
