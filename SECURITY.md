# Security Policy

## 🔒 Reporting Security Vulnerabilities

The security of the RIFT protocol specification is a top priority. If you discover a security vulnerability in the specification or reference implementation, please report it responsibly.

### Scope

Security issues include:
- **Protocol Design Flaws**: Vulnerabilities in the cryptographic design, state machine, or wire format that could compromise security
- **Ambiguities Leading to Insecure Implementations**: Unclear specification text that could lead implementers to create insecure code
- **Denial of Service Vectors**: Protocol features that could be exploited for DoS attacks
- **Privacy Leaks**: Unintended information disclosure through packet analysis
- **Replay Attacks**: Insufficient anti-replay protection
- **Man-in-the-Middle**: Weaknesses in handshake or key derivation

### How to Report

**DO NOT** open a public GitHub issue for security vulnerabilities.

Instead, please report security issues via:

📧 **Email**: ecsiar@gmail.com

Include the following information:

```
Subject: [SECURITY] Brief description

1. Description of the vulnerability
2. Affected section(s) of the specification
3. Potential impact (confidentiality/integrity/availability)
4. Proof of concept (if applicable)
5. Suggested mitigation (if you have one)
6. Whether you want public credit for the discovery
```

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 7 days
- **Fix Timeline**: Depends on severity
  - Critical: 14-30 days
  - High: 30-60 days
  - Medium/Low: 60-90 days
- **Public Disclosure**: After fix is ready and coordinated

### Coordinated Disclosure

We follow responsible disclosure practices:

1. **Private Notification**: We will acknowledge your report privately
2. **Fix Development**: We will work on a fix and update the specification
3. **Notification to Implementers**: Known implementers will be notified before public disclosure
4. **Public Disclosure**: A security advisory will be published with credit to the discoverer (if desired)

---

## 🛡️ Security Considerations

### Threat Model

RIFT is designed to protect against:

✅ **Passive Eavesdropping**: All application data is encrypted (AEAD)
✅ **Active Tampering**: Authentication tags prevent packet modification
✅ **Replay Attacks**: Anti-replay mechanisms for 0-RTT and tokens
✅ **Connection Hijacking**: Connection IDs are cryptographically validated
✅ **DoS Amplification**: Address validation before resource commitment

RIFT does **NOT** protect against:

❌ **Endpoint Compromise**: If client or server is compromised, security is lost
❌ **Traffic Analysis**: Packet sizes, timing, and patterns may leak metadata (use v2.x Stealth mode for additional protection)
❌ **State-Level Adversaries**: Not designed for Tor-level anonymity (unless using v2.x multi-hop relay)
❌ **Side-Channel Attacks**: Implementation-dependent (not protocol-level)

### Known Security Considerations

The following security considerations are documented in the specification:

#### Cryptographic Primitives (Section 5.1)
- **Noise IK Pattern**: Requires client to know server's static public key (prevents MITM but requires key distribution)
- **ChaCha20-Poly1305**: AEAD with 128-bit security level
- **X25519**: Elliptic curve for key agreement
- **Post-Quantum**: v2.0 adds hybrid X25519+Kyber768 for quantum resistance

#### 0-RTT Early Data (Section 5.5)
- **Replay Risk**: 0-RTT data can be replayed by attackers
- **Mitigation**: Server MUST use anti-replay filter, only idempotent frames allowed
- **Restrictions**: STREAM/DATAGRAM prohibited in 0-RTT

#### Header Protection (Section 4.5.3)
- **Purpose**: Prevents ossification, not confidentiality
- **Limitation**: Packet numbers are protected but not encrypted
- **Note**: Do not rely on HP for strong confidentiality

#### Path Validation (Section 10.1)
- **Off-Path Attacks**: PATH_CHALLENGE/PATH_RESPONSE prevents address spoofing
- **On-Path Attacks**: Active on-path attacker can still intercept (mitigated by AEAD)

#### Connection Migration (Section 10.2)
- **NAT Rebinding**: Accepted after path validation
- **Amplification Risk**: Address validation required before sending large amounts of data

---

## 🔐 Cryptographic Agility

RIFT is designed with cryptographic agility in mind:

### Current Algorithms (v1.0)
- **Key Exchange**: X25519 (ECDH)
- **AEAD**: ChaCha20-Poly1305 or AES-128-GCM
- **Hashing**: BLAKE2s (Noise) or SHA-256
- **Header Protection**: ChaCha20

### Future-Proofing (v2.0+)
- **Post-Quantum**: Hybrid X25519+Kyber768
- **Algorithm Negotiation**: Via transport parameters
- **Versioning**: New versions can introduce new crypto suites

### Deprecation Policy

If a cryptographic primitive is broken:

1. **Immediate Advisory**: Public security advisory published
2. **Specification Update**: Deprecated algorithm marked as MUST NOT use
3. **Grace Period**: 90 days for implementations to update
4. **Enforcement**: After grace period, connections using deprecated crypto MUST be rejected

---

## 🚨 Security Advisories

### Published Advisories

(None yet - this is the first release)

Future advisories will be published at:
- GitHub Security Advisories: https://github.com/rokoss21/rift-spec/security/advisories
- Mailing list: ecsiar@gmail.com

### Severity Ratings

We use CVSS v3.1 for severity ratings:

| Severity | CVSS Score | Example |
|----------|------------|---------|
| **Critical** | 9.0-10.0 | Remote code execution, complete bypass of crypto |
| **High** | 7.0-8.9 | Significant data leak, practical MITM |
| **Medium** | 4.0-6.9 | Denial of service, limited information disclosure |
| **Low** | 0.1-3.9 | Minor information leak, requires local access |

---

## 🧑‍💻 Security Review

### Completed Reviews

- **Internal Review**: Completed by specification author (Emil Rokossovskiy)
- **Community Review**: Ongoing (RC1 phase)

### Requested Reviews

We welcome security reviews from:
- Academic researchers
- Cryptography experts
- Protocol security specialists
- Professional security auditors

If you're interested in conducting a formal security review, please contact: ecsiar@gmail.com

---

## 📚 Security Resources

### References

- [RFC 7748](https://tools.ietf.org/html/rfc7748): X25519 and X448 Elliptic Curves
- [RFC 8439](https://tools.ietf.org/html/rfc8439): ChaCha20 and Poly1305
- [Noise Protocol Framework](https://noiseprotocol.org/): Cryptographic handshake patterns
- [RFC 9000](https://tools.ietf.org/html/rfc9000): QUIC (for comparison)

### Further Reading

- Section 15: Security Considerations (in RIFT-SPEC-RC1.md)
- Noise IK Pattern: https://noiseprotocol.org/noise.html#interactive-patterns

---

## 🏆 Hall of Fame

Security researchers who responsibly disclose vulnerabilities will be acknowledged here (with permission):

(None yet)

---

## ⚖️ Legal

This security policy applies to:
- The RIFT protocol specification
- Reference implementations (when available)
- Official tools and libraries

It does NOT apply to:
- Third-party implementations (contact respective authors)
- Forks of the specification
- Derivative works

---

**Thank you for helping keep RIFT secure!** 🔒

For any questions about this security policy, contact: ecsiar@gmail.com
