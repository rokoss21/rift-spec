# Contributing to RIFT Specification

Thank you for your interest in contributing to the RIFT Transport Protocol Specification! This document provides guidelines for contributing.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How to Contribute](#how-to-contribute)
- [Reporting Issues](#reporting-issues)
- [Submitting Changes](#submitting-changes)
- [Specification Versioning](#specification-versioning)
- [Style Guidelines](#style-guidelines)

---

## 🤝 Code of Conduct

This project adheres to a code of professional conduct:
- Be respectful and inclusive
- Focus on technical merit
- Provide constructive feedback
- Assume good faith

Unacceptable behavior will not be tolerated.

---

## 🛠️ How to Contribute

### Types of Contributions

We welcome the following types of contributions:

1. **Errata Corrections** ✏️
   - Typos, grammar, formatting issues
   - Technical inaccuracies in the specification
   - Broken links or references

2. **Clarifications** 💡
   - Ambiguous text that could lead to implementation incompatibilities
   - Missing details that make implementation difficult
   - Unclear requirements or behavior descriptions

3. **Test Vectors** 🧪
   - Golden vectors for packet encoding/decoding
   - Test cases for edge conditions
   - Interoperability test scenarios

4. **Extensions (v2.x+)** 🚀
   - New frame types (using reserved ranges)
   - New transport parameters
   - Anti-censorship enhancements

### What NOT to Contribute (v1.0 Wire Format)

**The v1.0 wire format is FROZEN**. The following are NOT accepted for v1.0:

- ❌ Changes to packet header formats
- ❌ Changes to existing frame formats
- ❌ Changes to cryptographic primitives
- ❌ Changes to assigned frame type numbers
- ❌ Breaking changes to PN space semantics

These may be considered for v2.x+ if there's strong justification.

---

## 🐛 Reporting Issues

### Before Reporting

1. **Search existing issues**: Check if the issue has already been reported
2. **Read the spec carefully**: Ensure it's actually an issue and not a misunderstanding
3. **Check RC1-CHANGES.md**: See if it was already addressed

### Issue Template

When reporting an issue, please include:

```markdown
**Section**: (e.g., Section 4.5.2 - Packet Number Usage)

**Issue Type**: [Ambiguity / Errata / Interop Problem / Question]

**Description**:
Clear description of the issue.

**Impact**:
How does this affect implementations?

**Proposed Fix** (if applicable):
Suggested correction or clarification.

**References**:
- Links to related discussions
- Affected implementation code (if relevant)
```

### Issue Labels

We use the following labels:

- `errata`: Typos, formatting, obvious corrections
- `clarification`: Ambiguous text needing clarification
- `interop`: Affects interoperability between implementations
- `v1.0-frozen`: Cannot be changed in v1.0 (move to v2.x)
- `v2.x-proposal`: Proposed extension for v2.x+
- `question`: General question about the specification
- `wontfix`: Issue is by design or out of scope

---

## 📝 Submitting Changes

### Pull Request Process

1. **Fork the repository**
   ```bash
   git clone https://github.com/rokoss21/rift-spec.git
   cd rift-spec
   git checkout -b fix/descriptive-name
   ```

2. **Make your changes**
   - Edit the specification document(s)
   - Follow the [Style Guidelines](#style-guidelines)
   - Update RC1-CHANGES.md if it's a significant fix

3. **Commit with clear messages**
   ```bash
   git commit -m "Fix ambiguity in Section 4.5.2 ACK delay interpretation"
   ```

4. **Push and create PR**
   ```bash
   git push origin fix/descriptive-name
   ```
   Then create a Pull Request on GitHub.

5. **PR Description Template**
   ```markdown
   **Type**: [Errata / Clarification / Extension]

   **Section(s) Affected**: (e.g., 4.5.2, 6.2)

   **Summary**:
   Brief description of the change.

   **Justification**:
   Why is this change necessary?

   **Impact**:
   - Does this affect existing implementations? (Yes/No)
   - Is this a breaking change? (Yes/No)
   - Does this require interop retesting? (Yes/No)

   **Related Issues**: Fixes #123
   ```

### Review Process

1. **Automatic Checks**: CI will run markdown linting
2. **Technical Review**: Maintainers will review for technical correctness
3. **Interop Impact**: Assessment of impact on existing implementations
4. **Approval**: At least one maintainer approval required
5. **Merge**: Squash and merge to main branch

---

## 📐 Specification Versioning

### Version Scheme

RIFT uses semantic versioning for the specification:

- **v1.0-RC1**: Release Candidate 1 (current, frozen)
- **v1.0**: Final release (after successful interop testing)
- **v1.1**: Minor updates (clarifications, non-breaking additions)
- **v2.0**: Major update (new features, possible breaking changes)

### Compatibility Rules

- **v1.x → v1.y**: MUST be wire-compatible
- **v1.x → v2.0**: MAY introduce breaking changes (version negotiation required)

---

## ✍️ Style Guidelines

### Markdown Formatting

- Use **ATX-style headers** (`#`, `##`, `###`)
- Use **fenced code blocks** with language specifiers
- Use **tables** for structured data
- Use **lists** (ordered/unordered) appropriately

### RFC 2119 Keywords

Use RFC 2119 keywords consistently:

- **MUST / MUST NOT**: Absolute requirement
- **SHOULD / SHOULD NOT**: Strong recommendation
- **MAY**: Optional behavior

Always capitalize these keywords for clarity.

### Technical Writing

- **Be precise**: Avoid ambiguous language ("should probably", "might", "usually")
- **Be concise**: Remove unnecessary words
- **Be consistent**: Use the same terminology throughout
- **Be normative**: State requirements clearly

### Example: Good vs Bad

❌ **Bad**:
```markdown
Implementations might want to send ACKs quickly for important packets.
```

✅ **Good**:
```markdown
Implementations MUST send ACK frames promptly (within max_ack_delay)
for packets containing HANDSHAKE or P0 priority frames.
```

### Section References

Use consistent section references:

```markdown
See Section 4.5.2 for PN reconstruction.
(Section 6.2)
As defined in Section 4.3.
```

### Code Examples

Use fenced code blocks with descriptive labels:

````markdown
```c
// Packet Number reconstruction (reference algorithm)
uint64_t reconstruct_pn(uint64_t largest_pn, uint64_t truncated_pn, uint8_t pn_len) {
    uint64_t pn_win = 1ULL << (pn_len * 8);
    uint64_t pn_hwin = pn_win / 2;
    uint64_t expected = largest_pn + 1;

    // ... (implementation)
}
```
````

---

## 🧪 Testing Contributions

### Golden Test Vectors

If contributing test vectors, provide:

1. **Input**: Packet bytes (hex)
2. **Keys**: Cryptographic keys used (hex)
3. **Expected Output**: Decrypted payload (hex)
4. **Parameters**: PN space, PN value, etc.

Example:
```json
{
  "test_name": "HP_removal_short_header",
  "packet_hex": "40ab...",
  "hp_key_hex": "1a2b...",
  "expected_pn": 12345,
  "expected_payload_hex": "..."
}
```

### Interop Test Cases

Describe test scenarios:

```markdown
**Test**: Path validation with NAT rebinding
**Setup**: Client behind NAT, server publicly reachable
**Steps**:
1. Client sends PATH_CHALLENGE from IP_1:Port_1
2. NAT changes client port to Port_2
3. Server receives from IP_1:Port_2
4. Server sends PATH_RESPONSE to IP_1:Port_2
5. Client receives and validates
**Expected**: Path validation succeeds despite port change
```

---

## 📧 Communication

### Preferred Channels

- **GitHub Issues**: For bugs, ambiguities, errata
- **GitHub Discussions**: For questions, design discussions
- **Email**: ecsiar@gmail.com (for sensitive issues)

### Response Time

- **Errata**: Typically reviewed within 3-5 days
- **Clarifications**: Reviewed within 1-2 weeks
- **Extensions**: May take longer, requires thorough review

---

## 🏆 Recognition

Contributors will be acknowledged in:
- **RC1-CHANGES.md**: For significant fixes
- **GitHub Contributors**: All merged PRs
- **Acknowledgments Section**: For major contributions

---

## ❓ Questions?

If you have questions about contributing:

1. Check [GitHub Discussions](https://github.com/rokoss21/rift-spec/discussions)
2. Read existing issues for similar questions
3. Open a new discussion or issue

---

**Thank you for contributing to RIFT!** 🚀

Your contributions help make RIFT a better protocol for real-time communications worldwide.
