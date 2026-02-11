# RIFT Transport Protocol Specification

[![Specification Status](https://img.shields.io/badge/Status-RC1%20Final-green.svg)](https://github.com/rokoss21/rift-spec)
[![Version](https://img.shields.io/badge/Version-1.0--RC1-blue.svg)](https://github.com/rokoss21/rift-spec/blob/main/RIFT-SPEC-RC1.md)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> **RIFT**: Realtime Interactive Fast Transport — A next-generation transport protocol for real-time communications (VoIP, video, collaboration) designed for mobile-first, multipath-native, and censorship-resistant environments.

## 📋 Overview

This repository contains the **official specification** for the RIFT Transport Protocol.

RIFT is designed to address the limitations of traditional transport protocols (TCP, QUIC) in real-time communication scenarios:
- ✅ **Seamless roaming** across network changes (Wi-Fi ↔ LTE) without connection drops
- ✅ **Low tail-latency** for audio/video even with packet loss and jitter
- ✅ **Multipath-native** with active-backup and duplication modes
- ✅ **Adaptive FEC** for resilience in poor network conditions
- ✅ **Built-in QoS scheduler** with programmable priority policies
- ✅ **Censorship-resistant** extensions (obfuscation, relay, fallback transports)

---

## 📖 Specification Documents

### Core Specification
📄 **[RIFT-SPEC-RC1.md](RIFT-SPEC-RC1.md)** — Main protocol specification (RC1 Final)
- **Status**: Release Candidate 1 (Final) ✓
- **Wire Format**: FROZEN for v1.0
- **Ready for**: Independent implementation and interoperability testing

### Supporting Documents
📝 **[RC1-CHANGES.md](RC1-CHANGES.md)** — Critical changes log
- Documents all interoperability fixes
- Verification checklist
- Confidence assessment

---

## 🚀 Quick Start

### For Protocol Implementers

1. **Read the specification**: Start with [RIFT-SPEC-RC1.md](RIFT-SPEC-RC1.md)
2. **Pay attention to critical sections**: Look for **CRITICAL (interop)** markers
3. **Implement conformance**: Follow all MUST/MUST NOT requirements (RFC 2119)
4. **Test interoperability**: Verify against other implementations

**Key Sections for First Implementation**:
- Section 4: Packetization and Header Formats
- Section 5: Cryptographic Handshake (Noise Framework)
- Section 6: Core Frames
- Section 7: Loss Recovery and Timers
- Section 8: Congestion Control and Pacing

### For Researchers

RIFT introduces several novel approaches:
- **Mobile-first multipath**: Seamless Wi-Fi/LTE handover without application-level reconnection
- **Noise-first crypto**: Lightweight alternative to TLS for transport-layer security
- **Adaptive FEC**: Dynamic forward error correction based on network conditions
- **Programmable QoS**: Application-controlled priority scheduling with deadlines

---

## 🏗️ What's Included

### v1.0 Core Protocol
- ✅ **Packet Formats**: Long/Short headers with Header Protection
- ✅ **Frame Types**: All core frames (ACK, STREAM, DATAGRAM, PATH_CHALLENGE, etc.)
- ✅ **Cryptography**: Noise IK pattern with ChaCha20-Poly1305
- ✅ **Loss Recovery**: ACK-based with PTO (Probe Timeout)
- ✅ **Congestion Control**: BBRv2 and Cubic support
- ✅ **Multipath**: Path validation, migration, active-backup, duplication
- ✅ **QoS Scheduler**: 4 priority classes (P0-P3) with deadline support
- ✅ **Forward Error Correction**: XOR and Reed-Solomon FEC

### v2.x Anti-Censorship Extensions
- 🔐 **Obfuscation**: obfs4, TLS-mimic, ShadowSocks transforms
- 🌐 **Relay Infrastructure**: Single-hop and multi-hop forwarding
- 🛡️ **Stealth Mode**: Port knocking, timing jitter, decoy traffic
- 🔄 **Fallback Transports**: TCP wrapper, WebSocket tunnel

### v3.x Universal Extensions (Non-Wire)
- 🌍 **TUN/TAP Integration**: VPN-like functionality
- 🔌 **SOCKS5 Proxy**: Transparent proxying
- 🎯 **Traffic Classification**: Application-aware routing

---

## 📊 Specification Status

### RC1 Final (February 10, 2026)
✅ **Wire format complete and frozen**
✅ **All critical ambiguities resolved**
✅ **Transport Parameters and Error Codes registries added**
✅ **Golden test vectors and conformance tests defined**
✅ **Interoperability-ready**
✅ **No known blocking issues**

### Conformance Requirements

Two independent implementations MUST be able to:
- [x] Complete Noise handshake (INITIAL → HANDSHAKE → 1-RTT)
- [x] Exchange STREAM and DATAGRAM frames
- [x] Process ACK frames correctly (PN space scoping)
- [x] Validate paths (PATH_CHALLENGE/PATH_RESPONSE with 5-tuple binding)
- [x] Handle packet loss and retransmission
- [x] Perform multipath operations
- [x] Apply Header Protection correctly
- [x] Construct AEAD nonces correctly

---

## 🔧 Implementation

### Reference Implementation
🦀 **Rust**: [rokoss21/rift-rs](https://github.com/rokoss21/rift-rs) (coming soon)
- Modular architecture (rift-wire, rift-crypto, rift-core, rift-io)
- v1.0 baseline + v2.x anti-censorship extensions
- Linux, Windows, macOS support

### Known Implementations
(Will be updated as implementations become available)

---

## 📐 Protocol Design Principles

1. **Mobile-First**: Optimized for LTE/Wi-Fi roaming and NAT traversal
2. **Realtime-Friendly**: Low latency (P0 audio < 50ms), deadline-aware scheduling
3. **Resilience**: Multipath, FEC, adaptive keep-alive
4. **Security**: Noise Protocol Framework, PFS, AEAD, Header Protection
5. **Observability**: RTT/loss/jitter metrics without decrypting payload
6. **Anti-Ossification**: Greasing, reserved bits, extensible frame types

---

## 🤝 Contributing

We welcome contributions to the specification! Here's how you can help:

### Reporting Issues
- 🐛 **Ambiguities**: Found unclear text? [Open an issue](https://github.com/rokoss21/rift-spec/issues)
- 🔍 **Interop Problems**: Implementation not compatible? [Report it](https://github.com/rokoss21/rift-spec/issues)
- 📝 **Errata**: Spotted a typo or technical error? [Submit a fix](https://github.com/rokoss21/rift-spec/pulls)

### Pull Requests
- Read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting
- For v1.0, the wire format is **frozen** — only clarifications/errata accepted
- For v2.x+ extensions, proposals are welcome

### Discussion
- 💬 **GitHub Discussions**: [Start a discussion](https://github.com/rokoss21/rift-spec/discussions)
- 📧 **Email**: ecsiar@gmail.com

---

## 📚 Additional Resources

### Documentation
- 📖 **Implementer's Guide**: (coming soon)
- 🧪 **Test Vectors**: [Appendix C - Interoperability Test Vectors](RIFT-SPEC-RC1.md#appendix-c-interoperability-test-vectors-rc1)
- 📊 **Performance Analysis**: (coming soon)

### Related Projects
- **RIFT-RS**: Reference Rust implementation
- **RIFT-CLI**: Command-line client for testing
- **RIFT-Server**: Production server implementation

---

## 📜 License

This specification is released under the **MIT License**. See [LICENSE](LICENSE) for details.

```
Copyright (c) 2026 Emil Rokossovskiy

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
```

---

## 🎯 Roadmap

### Phase 1: v1.0 Foundation (Current)
- [x] Complete wire specification (RC1)
- [x] Golden test vectors (Appendix C)
- [x] Conformance test plan (22-point checklist)
- [ ] Reference implementation (rift-rs)
- [ ] Interoperability testing

### Phase 2: v2.0 Anti-Censorship
- [ ] Obfuscation layer implementation
- [ ] Relay infrastructure deployment
- [ ] Field testing in censored regions
- [ ] Performance optimization

### Phase 3: v3.0 Universal Extensions
- [ ] TUN/TAP integration
- [ ] SOCKS5 proxy support
- [ ] Traffic classification engine
- [ ] VPN-like features

---

## 👤 Author

**Emil Rokossovskiy**
- GitHub: [@rokoss21](https://github.com/rokoss21)
- Email: ecsiar@gmail.com

---

## 🌟 Acknowledgments

Special thanks to:
- QUIC Working Group for protocol design inspiration
- Noise Protocol Framework authors for elegant cryptographic handshake design
- obfs4 and ShadowSocks projects for censorship resistance techniques

---

## 📊 Quick Reference

### Core Frame Types (v1.0)
| Type | Name | Purpose |
|------|------|---------|
| `0x00` | FRAME_BUNDLE | Frame bundling container |
| `0x01` | ACK | Acknowledge packets |
| `0x10` | PING | Liveness probe |
| `0x11` | PONG | Ping response |
| `0x12` | PATH_CHALLENGE | Path validation |
| `0x13` | PATH_RESPONSE | Path validation response |
| `0x20` | STREAM | Reliable byte stream |
| `0x30` | DATAGRAM | Unreliable datagram |
| `0x40` | NEW_TOKEN | 0-RTT token issuance |
| `0x50` | CC_EVENT | Congestion control feedback |
| `0x62` | NEW_CONNECTION_ID | CID rotation |
| `0x64` | CONNECTION_CLOSE | Terminate connection |

### Critical Constraints
- **CID Length**: [0, 20] bytes, fixed for connection lifetime
- **PN Spaces**: INITIAL, HANDSHAKE, 1-RTT (independent)
- **ACK Scoping**: Within PN space only (no cross-PN-space ACKs)
- **Path Validation**: Bound to 5-tuple, not PathID

---

## 📈 Citation

If you use RIFT in academic work, please cite:

```bibtex
@techreport{rokossovskiy2026rift,
  title={RIFT Transport Protocol Specification (RC1)},
  author={Rokossovskiy, Emil},
  year={2026},
  institution={RIFT Protocol Project},
  url={https://github.com/rokoss21/rift-spec}
}
```

---

**Repository**: https://github.com/rokoss21/rift-spec
**Status**: RC1 Final — Ready for Implementation 🚀
**Last Updated**: February 10, 2026
