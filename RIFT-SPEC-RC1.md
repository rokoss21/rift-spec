# RIFT Transport Protocol Specification (RC1)

**Status**: Release Candidate 1 (Final) ✓
**Version**: 1.0-RC1
**Date**: February 10, 2026
**Author**: Emil Rokossovskiy
**Repository**: https://github.com/rokoss21/rift-spec
**Scope**: v1.0 Core + v2.x Anti-Censorship extensions + v3.x Universal (non-wire) layering

---

This document is a normative wire and behavior specification for the RIFT protocol family.
It is intended to be read like an RFC-style RC document.

**RC1 Status**: This specification is internally consistent, complete, and ready for independent implementation and interoperability testing. All critical ambiguities have been resolved. The wire format is frozen for v1.0.

**Citation**:
```
Rokossovskiy, E. (2026). RIFT Transport Protocol Specification (RC1).
Retrieved from https://github.com/rokoss21/rift-spec
```

NOTE (implementation reality): the repository currently contains a bootstrap prototype. This spec describes the target protocol design derived from `rift.prd`; some sections are not implemented yet.

## Contents

- 1. Conventions and Terminology
- 2. Encoding Primitives
- 3. Protocol Overview
- 4. Packetization and Header Formats
- 5. Cryptographic Handshake (Noise-first)
- 6. Frames (Core)
- 7. Loss Recovery and Timers
- 8. Congestion Control and Pacing
- 9. QoS Scheduler and Priority Classes
- 10. Multipath, Migration, and Keep-Alive
- 11. Forward Error Correction (FEC)
- 12. Observability
- 13. Anti-Censorship Extensions (v2.x)
- 14. Universal Extensions (v2.5-v3.x, non-wire)
- 15. Security Considerations
- Appendix A. Frame Registry (RC1)
- Appendix P. Bootstrap Prototype Mapping (Informative)
- Appendix B. Connection State Machine (high level)

## 1. Conventions and Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in RFC 2119 and RFC 8174.

### 1.1. Roles

- Endpoint: a protocol participant.
- Client: initiates a connection.
- Server: accepts a connection.
- Relay: forwards RIFT packets between a client and an origin server (v2.x extension).

### 1.2. Identifiers and Spaces

- Connection ID (CID): an opaque identifier for demultiplexing and migration.
- Path: a tuple (local_addr, remote_addr, local_port, remote_port, transport).
- Path ID (PathID): an endpoint-assigned identifier for a validated path.
- Packet Number (PN): a monotonically increasing number for loss/reorder handling.
- PN Space: independent packet numbering space scoped to cryptographic protection level (INITIAL, HANDSHAKE, 1-RTT). Each PN space has independent PN sequencing and ACK tracking.
- Stream ID (StreamID): identifier of a stream within a connection.

### 1.3. Types

- Byte order: network byte order (big-endian) unless specified.
- VarInt: QUIC-style variable-length unsigned integer (Section 2).
- Time units: milliseconds unless specified.

## 2. Encoding Primitives

### 2.1. VarInt (QUIC-style)

RIFT uses QUIC-style VarInt:

- 00: 1 byte, payload 6 bits
- 01: 2 bytes, payload 14 bits
- 10: 4 bytes, payload 30 bits
- 11: 8 bytes, payload 62 bits

Endpoints MUST reject non-canonical encodings.

### 2.2. Frames and Bundling

RIFT packets carry one or more "frames" inside the authenticated encryption payload.
An endpoint MUST be prepared to process multiple frames per packet.

Frame type encoding:

- Frame Type is a VarInt.
- This enables extension without ossification around a fixed 1-byte type space.

RIFT defines an explicit bundling frame:

- FRAME_BUNDLE: a container that carries multiple inner frames.
- Endpoints MAY also accept "single frame payloads" as legacy encoding during transition.

Bundle nesting:

- FRAME_BUNDLE MUST NOT be nested.
- A FRAME_BUNDLE MUST contain only non-bundle frames.

FRAME_BUNDLE format (frame type = 0x00):

- type: VarInt (value 0x00)
- repeated:
  - len: u16
  - frame_bytes: [len] bytes

Inner frames start with their VarInt-encoded frame type.

**CRITICAL (interop): FRAME_BUNDLE encoding**

- `len` is a fixed 2-byte unsigned integer (u16) in **network byte order** (big-endian), NOT a VarInt.
- `len` specifies the total length of `frame_bytes` in bytes, including the VarInt frame type prefix of the inner frame.
- Each `frame_bytes` sequence MUST be a complete, valid frame starting with its VarInt type field.
- Implementations MUST validate that each inner frame is well-formed before processing.
- If any inner frame is malformed, the entire FRAME_BUNDLE MUST be discarded.
- The bundle repeats until the end of the AEAD-decrypted payload.
- **After processing all (len, frame_bytes) pairs, there MUST be no remaining bytes in the FRAME_BUNDLE payload.**
- **If any bytes remain after the last frame_bytes, the entire FRAME_BUNDLE MUST be discarded.**

**Error handling for malformed FRAME_BUNDLE**:
- A malformed FRAME_BUNDLE (trailing bytes, invalid inner frame, len inconsistency) MUST cause the **packet** to be dropped.
- Endpoints MUST NOT immediately close the connection for a single malformed FRAME_BUNDLE.
- Endpoints MAY treat **repeated** malformed FRAME_BUNDLE (e.g., 3+ consecutive packets) as a protocol error and close the connection with error code `INVALID_FRAME_BUNDLE` (0x12).
- Implementations MUST rate-limit connection closes to prevent DoS via intentionally malformed packets.

Example:
```
FRAME_BUNDLE containing PING (nonce: 0x0102030405060708):
  type: 0x00 (FRAME_BUNDLE, 1 byte VarInt)
  len: 0x0009 (9 bytes big-endian u16)
  frame_bytes: 0x10 0x0102030405060708 (PING type + 8-byte nonce)
Total: 1 + 2 + 9 = 12 bytes
```

## 3. Protocol Overview

RIFT is a UDP-first transport protocol optimized for realtime applications, with:

- Encrypted frames (no cleartext semantics beyond what is required for demux).
- Streams (reliable, ordered byte streams) and datagrams (unreliable, unordered).
- Scheduler-defined priorities P0..P3 that drive pacing, dropping, duplication, and FEC.
- Multipath and migration as first-class.
- Optional anti-censorship (obfuscation, fallback transports, relay) as feature-gated modules.
- Optional universal layering (TUN/proxy/adapters) above core, without changing core wire.

## 4. Packetization and Header Formats

### 4.1. Versioning

RIFT has an explicit version field in long headers.
Version is a VarInt.

Endpoints MUST implement version negotiation. Unknown versions MUST be rejected with a Version Negotiation response (Section 4.6) unless policy forbids.

### 4.2. Header Forms

RIFT defines two header forms:

- Long Header: used for connection establishment, retry, and key negotiation.
- Short Header: used for 1-RTT protected packets during an established connection.

### 4.3. Long Header (wire layout)

Long Header fields:

- first_byte: u8
  - bit 7: header_form = 1
  - bit 6: fixed_bit = 1
  - bits 5..4: pn_len (00=1, 01=2, 10=3, 11=4)
  - bits 3..0: long_type (packet type)
- version: VarInt
- dcid_len: VarInt
- dcid: [dcid_len] bytes
- scid_len: VarInt
- scid: [scid_len] bytes
- token_len: VarInt
- token: [token_len] bytes
- payload_len: VarInt (length of the remaining packet)
- pn_len: 2 bits encoded in first_byte (pn_len = 1,2,3,4 bytes)
- pn: packet number (truncated to pn_len)
- protected_payload: bytes (AEAD ciphertext + tag)

**Connection ID length constraints**

Both dcid_len and scid_len MUST represent CID lengths in the range [0, 20] bytes inclusive.
Packets with dcid_len or scid_len values outside this range MUST be dropped.

The CID length established during the handshake is fixed for the lifetime of the connection (see Section 4.4).

Token encoding:

- token_len is present in all Long Header packets.
- For non-INITIAL Long Header packets, token_len MUST be encoded as VarInt(0) and token omitted.
- All Long Header packets in RC1 include the token_len field. Receivers MUST treat absence of token_len as a format error and drop the packet.

#### 4.3.1. Long Header Packet Types (RC1)

In RC1, all Long Header packet types share the same header field layout up to and including the PN field.
Any future version introducing long_type-specific header fields MUST define pn_offset derivation per packet type.

long_type values (in first_byte bits 3..0, after HP removal):

- 0x0: INITIAL
- 0x1: RETRY
- 0x2: HANDSHAKE
- 0x3..0xF: RESERVED (MUST be dropped)

Long Header type handling:

- Endpoints MUST drop packets with unknown or RESERVED long_type values.
- Long Header packet type values carry semantics and MUST NOT be validated against fixed bit patterns beyond this registry.

Long Header reserved bits:

- In RC1, Long Header has no additional reserved bits beyond the long_type field.
- Future versions defining Long Header reserved bits MUST specify receiver processing rules; receivers SHOULD ignore such bits by default.

### 4.4. Short Header (wire layout)

Short Header fields:

- first_byte: u8
  - bit 7: header_form = 0
  - bit 6: fixed_bit = 1
  - bit 5: key_phase (KP)
  - bits 4..3: pn_len (00=1, 01=2, 10=3, 11=4)
  - bits 2..0: reserved (MUST be greased occasionally)
- dcid: connection ID (length negotiated during handshake)
- pn: packet number (truncated)
- protected_payload: bytes

The destination CID length used in Short Header packets is fixed for the lifetime of the connection.

Greasing and PN length:

- Bits used to encode pn_len MUST be distinct from bits used for greasing.
- Reserved bits MUST be set to a non-constant pattern over time (greasing), but MUST NOT
  change the interpretation of pn_len.
- Receivers MUST ignore reserved bits.
- Senders MUST set fixed_bit to 1. Packets with fixed_bit != 1 MUST be dropped and MUST NOT elicit a response.

### 4.5. Packet Protection

RIFT uses:

- AEAD for payload confidentiality and integrity.
- Header protection (HP) to protect PN and selected header bits, to prevent ossification.

Endpoints MUST apply HP after payload protection, and remove HP before payload decryption.

#### 4.5.1. AEAD

RC1 baseline AEAD:

- ChaCha20-Poly1305 (preferred) or AES-128-GCM (optional).

AEAD tag:

- All AEAD algorithms used by RIFT produce a 16-byte authentication tag.

Associated Data (AD):

The AEAD "associated data" (AD) MUST be the unprotected header bytes from the
packet start (first_byte) through and including the Packet Number field, with
header protection removed.

The associated data is constructed as the exact sequence of header bytes as they
appear on the wire after HP removal, without any re-encoding, normalization, or
field re-serialization.

This fixes AD unambiguously and prevents interop divergence.

For Long Header packets, AD includes:

- first_byte (unmasked)
- version
- dcid_len, dcid
- scid_len, scid
- token_len, token
- payload_len
- pn (truncated, pn_len bytes; after unmasking first_byte to learn pn_len)

For Short Header packets, AD includes:

- first_byte (unmasked)
- dcid
- pn (truncated, pn_len bytes; after unmasking first_byte to learn pn_len)

At minimum, AD therefore binds header_form, packet type, version (long), CID(s),
pn_len, PN, and protected header bits.

#### 4.5.2. Packet Number Usage

Packet number (PN) spaces are scoped by cryptographic packet protection level.
RC1 defines three PN spaces:

- INITIAL
- HANDSHAKE
- 1-RTT

Packet numbers are monotonically increasing within each PN space independently.
PN reconstruction, ACK processing, and loss recovery operate within the PN space corresponding to the keys
used to protect the packet. Key updates within 1-RTT do not create a new PN space.

Within a given PN space, PN is a per-connection number space by default (simplifies duplication/multipath).
PN MUST be strictly increasing per sender per PN space.

Receivers MUST accept out-of-order delivery and MUST NOT require contiguous PN.

Packet number exhaustion:

- Implementations MUST treat PN as an effectively unbounded integer.
- Implementations MUST NOT wrap packet numbers.
- If an endpoint would exceed PN >= 2^62-1 for a PN space, it MUST close the connection.

Packet number truncation:

- Senders encode PN using 1..4 bytes (pn_len).
- Receivers MUST reconstruct the full PN using the truncated value and the
  "largest received PN" for that PN space (QUIC-style).

Reference reconstruction (non-normative):

1. expected = largest_received + 1
2. pn_win = 1 << (pn_len * 8)
3. pn_hwin = pn_win / 2
4. pn_mask = pn_win - 1
5. candidate = (expected & ~pn_mask) | truncated_pn
6. if candidate + pn_hwin <= expected: candidate += pn_win
7. if candidate > expected + pn_hwin and candidate >= pn_win: candidate -= pn_win
8. full_pn = candidate

#### 4.5.3. Header Protection Algorithm

HP is QUIC-like and is REQUIRED for interoperability.

Header protection (HP) MUST be applied after payload protection and removed
before payload decryption.

##### 4.5.3.1. Sample and Mask Generation

Definitions:

- packet_bytes: the entire packet as received, starting at first_byte.
- pn_offset: the byte offset of the first PN byte in the packet.
- sample_offset: pn_offset + 4
- sample_len: 16 bytes

pn_offset derivation:

- Short Header: pn_offset = 1 + dcid_len (dcid_len is known from handshake)
- Long Header: pn_offset is the offset immediately following payload_len
  (and token_len/token, which are in cleartext)

To compute the mask:

1. Let sample be the 16 bytes of packet_bytes starting at sample_offset.
2. Compute mask = HP(hp_key, sample), where mask is at least 5 bytes.

Packets MUST be dropped if packet_bytes is not long enough to provide the sample.

Length precheck:

- Let packet_length be the length of packet_bytes in bytes.
- If packet_length < (pn_offset + 4 + sample_len), the packet MUST be dropped before any further processing.

HP function (RC1):

The HP function depends on the negotiated AEAD:

- For AES-128-GCM:
  - hp_key length: 16 bytes
  - mask = AES-ECB(hp_key, sample)
  - use mask_bytes = first 5 bytes of mask

- For ChaCha20-Poly1305:
  - hp_key length: 32 bytes
  - counter = u32_le(first 4 bytes of sample)
  - nonce = bytes 4..15 of sample (12 bytes)
  - mask_stream = ChaCha20(key=hp_key, nonce=nonce, counter=counter)
  - use mask_bytes = first 5 bytes of mask_stream keystream

##### 4.5.3.2. Mask Application

Let pn_len be the decoded PN length (1..4).

Long Header:

- Apply: first_byte ^= (mask[0] & 0x0f)
  - This masks bits 0..3: reserved bits (bits 2-3) and pn_len (bits 0-1).
  - Long_type (bits 4-5), header_form (bit 7), and fixed_bit (bit 6) MUST remain unchanged.

Short Header:

- Apply: first_byte ^= (mask[0] & 0x1f)
  - This masks bits 0..4: reserved bits (bits 3-4), key_phase (bit 2), and pn_len (bits 0-1).
  - Header_form (bit 7) and fixed_bit (bit 6) MUST remain unchanged.

Packet Number:

- For i = 0 to pn_len-1:
  - pn_byte[i] ^= mask[1 + i]

##### 4.5.3.3. Chicken-and-Egg Resolution

Receivers MUST compute sample_offset as pn_offset + 4 (not pn_offset + pn_len).
This allows removing HP without knowing pn_len ahead of time.

**CRITICAL (interop): pn_offset independence**

- `pn_offset` is computed based solely on cleartext header fields (header form, CID lengths) and does NOT depend on `pn_len`.
- `pn_len` is determined only AFTER HP removal, by decoding the unmasked first_byte bits.
- This ordering is essential: compute pn_offset → sample → unmask first_byte → decode pn_len.

RC1 requires that HP protect:

- PN bytes (all header forms)
- pn_len field (bits 0-1 of first_byte)
- Reserved bits (bits 2-3 in Long Header, bits 3-4 in Short Header)
- key_phase bit (bit 2 in Short Header only)
- Long Header: does NOT protect long_type (bits 4-5) or version/CID fields
- Short Header: does NOT protect spin bit (bit 5) or fixed_bit/header_form (bits 6-7)

##### 4.5.3.4. HP Removal Procedure (Receiver)

Receivers MUST remove header protection in the following order:

1. Parse the unprotected portion of the header to compute pn_offset (Section 4.5.3.1).
2. **Length precheck**: If `packet_length < (pn_offset + 4 + 16)`, the packet MUST be dropped immediately.
   This rule applies even if AEAD decryption would otherwise be possible; insufficient length for HP sampling MUST cause immediate packet discard before any cryptographic processing.
3. Take sample as the 16 bytes starting at offset (pn_offset + 4) in packet_bytes.
4. Compute mask = HP(hp_key, sample).
5. Unmask first_byte using mask[0] (Section 4.5.3.2) to recover key_phase, pn_len bits, and (depending on header form) long_type or reserved bits.
6. Decode pn_len (1..4) from the now-unmasked first_byte.
7. Unmask the PN field (pn_len bytes starting at pn_offset) using mask[1..] (Section 4.5.3.2).
8. Reconstruct the full PN (Section 4.5.2), then perform payload decryption and frame parsing.

### 4.6. Version Negotiation (VN)

If a server receives a Long Header with an unsupported version, it MAY reply with VN:

- VN packet is not encrypted.
- VN contains a list of supported versions.

VN packet format (RC1):

- first_byte: u8 (Long Header form, fixed_bit set; remaining bits randomized)
- version: VarInt(0)
- dcid_len, dcid: echo the client's SCID from the triggering Initial
- scid_len, scid: echo the client's DCID from the triggering Initial (if present; otherwise empty)
- supported_versions: a sequence of VarInt versions

**CRITICAL (interop): VN is unprotected**

- VN packets MUST NOT be processed through Header Protection (HP) or AEAD.
- Receivers MUST NOT attempt to compute pn_offset, sample, or apply HP removal for VN packets.
- VN is a distinct unprotected packet type that uses the Long Header form bit but does NOT follow the standard Long Header packet format (no token_len, payload_len, PN, or protected_payload fields).

Notes:

- In VN packets the lower 6 bits of first_byte carry no semantic meaning and are treated purely as opaque greasing bits.
- supported_versions is a sequence of VarInt values that extends to the end of the UDP datagram. No explicit length field is present.
- VN packets MUST contain at least one supported version. Packets with an empty supported_versions list MUST be ignored.

Client validation (minimum):

- The client MUST match VN to an outstanding Initial by validating that the VN dcid equals
  the client's Initial SCID.
- If validation fails, the VN MUST be ignored.

This mitigates off-path VN injection.

### 4.7. Packet Size, PMTU, and Minimum Support

RIFT is UDP-first. To maximize real-world reach, endpoints MUST support a minimum UDP
payload size.

- Endpoints MUST support sending and receiving UDP datagrams with at least 1200 bytes payload.
- Endpoints MUST NOT send UDP packets larger than the peer's advertised max_udp_payload_size.
- Oversized packets MUST be dropped.
- Oversized packets MUST NOT elicit a response.

PMTU discovery:

- Implementations SHOULD perform PMTU discovery / black-hole detection and adapt the
  effective max_udp_payload_size downward if loss patterns indicate fragmentation black-holes.

## 5. Cryptographic Handshake (Noise-first)

### 5.1. Baseline Pattern

RC1 baseline handshake uses Noise Protocol Framework:

- Pattern: IK
- DH: X25519
- Cipher: ChaChaPoly
- Hash: BLAKE2s

Notation: Noise_IK_25519_ChaChaPoly_BLAKE2s.

Client MUST pin the server static public key via configuration or trusted distribution.
Servers MUST rotate connection keys (Key Update) during long-lived sessions.

### 5.1.1. Server Key Distribution and Rotation

RIFT IK requires clients to know a server static public key.
This specification does not mandate one distribution model; deployments MUST choose at least one:

- Configuration: key delivered with the application configuration (recommended for controlled deployments).
- Trusted directory: key fetched from a trusted directory with out-of-band trust anchors.
- TOFU (Trust On First Use): key learned on first connection, stored, and pinned for subsequent connections (NOT RECOMMENDED for high-risk censorship environments without additional checks).

Key rotation:

- Servers SHOULD support key rotation via publishing multiple valid server public keys for an overlap period.
- Clients SHOULD support a key set (pinset) rather than a single key to allow rotation without hard outages.

### 5.1.2. Key Schedule (RC1)

RIFT uses the Noise "Split" output as the root for directional packet protection.

At handshake completion, Noise yields two directional secrets:

- secret_c2s: client to server
- secret_s2c: server to client

For each direction, derive:

- aead_key = KDF(secret, "rift aead key", key_len)
- aead_iv  = KDF(secret, "rift aead iv", 12)
- hp_key   = KDF(secret, "rift hp key", hp_key_len)

KDF MUST be an HKDF-like expansion with a collision-resistant hash.
RC1 RECOMMENDS HKDF-SHA256 for KDF expansion even if Noise uses BLAKE2s internally,
to align with common implementations and cryptographic review practices.

Noise boundary:

- The Noise handshake transcript and chaining hash remain based on the Noise hash function (BLAKE2s).
- HKDF-SHA256 is used only for post-handshake key expansion from the Noise Split output.

Nonce construction for AEAD:

- AEAD nonce is 12 bytes.
- The PN used for nonce construction MUST be the full reconstructed packet number in that PN space (Section 4.5.2),
  truncated modulo 2^64 for encoding into pn_u64_be.
- Let pn_u64_be = encode_u64_be(pn).
- Let pn_pad = 0x00000000 || pn_u64_be (12 bytes).
- nonce = aead_iv XOR pn_pad.

### 5.2. Handshake Phases and Packets

Handshake uses Long Header packets:

- INITIAL: carries client Noise message 1 and transport parameters.
- RETRY: stateless server response carrying an address validation token.
- HANDSHAKE: carries server Noise message 2 and transport parameters.

Application data is sent only in 1-RTT Short Header packets, except for limited 0-RTT early data (Section 5.5).

### 5.3. Transport Parameters

Transport parameters are carried inside encrypted handshake frames and are authenticated.
Parameters include (non-exhaustive):

- max_udp_payload_size (peer's maximum UDP payload size in bytes; minimum supported is 1200)
- idle_timeout
- initial_max_data
- initial_max_stream_data
- initial_max_streams_bidi / uni
- ack_delay_exponent
- max_ack_delay
- active_connection_id_limit
- supported_cc_algorithms (cubic, bbrv2)
- supported_fec_schemes (xor, rs)
- supported_obfs_transforms (v2.x)
- anti_censorship_level (v2.x)

Transport parameters are interpreted in the context of the negotiated protocol version.
An endpoint receiving parameters inconsistent with the negotiated version MUST fail the connection attempt.

#### 5.3.1. Transport Parameter Encoding and Criticality

Transport Parameters are encoded as:

- param_id: VarInt
- length: VarInt
- value: [length] bytes

Criticality rule:

- A parameter is "critical" if (param_id & 1) == 1 (odd).
- Unknown critical parameters MUST cause the connection attempt to fail.
- Unknown non-critical parameters MUST be ignored.

This enables greasing (allocate even IDs) and forward compatibility without ambiguity.

Greasing:

- Endpoints SHOULD grease by sending unknown non-critical (even) param_id values with random lengths and values.

#### 5.3.2. Transport Parameter Registry (RC1)

The following transport parameters are defined for RIFT v1.0-RC1:

| Param ID | Name | Type | Critical | Default | Description |
|----------|------|------|----------|---------|-------------|
| `0x00` | max_udp_payload_size | VarInt | No | 65527 | Maximum UDP payload size in bytes (MUST be >= 1200) |
| `0x01` | idle_timeout | VarInt | Yes | (none) | Idle timeout in milliseconds (0 = disabled) |
| `0x02` | initial_max_data | VarInt | No | 65536 | Initial connection-level flow control limit (bytes) |
| `0x03` | initial_max_stream_data_bidi_local | VarInt | No | 32768 | Initial stream-level flow control for local bidi streams |
| `0x04` | initial_max_stream_data_bidi_remote | VarInt | No | 32768 | Initial stream-level flow control for remote bidi streams |
| `0x05` | initial_max_stream_data_uni | VarInt | No | 32768 | Initial stream-level flow control for unidirectional streams |
| `0x06` | initial_max_streams_bidi | VarInt | No | 100 | Initial maximum number of bidirectional streams |
| `0x07` | initial_max_streams_uni | VarInt | No | 100 | Initial maximum number of unidirectional streams |
| `0x08` | ack_delay_exponent | VarInt | No | 3 | Exponent used to decode ack_delay (range: [0, 20]) |
| `0x09` | max_ack_delay | VarInt | No | 25 | Maximum ACK delay in milliseconds (default 25ms) |
| `0x0a` | active_connection_id_limit | VarInt | No | 2 | Maximum number of active Connection IDs (MUST be >= 2) |
| `0x0c` | supported_cc_algorithms | byte array | No | 0x01 | Bitmap: bit 0 = Cubic, bit 1 = BBRv2 |
| `0x0e` | supported_fec_schemes | byte array | No | (none) | Bitmap: bit 0 = XOR, bit 1 = Reed-Solomon |
| `0x10` | max_datagram_frame_size | VarInt | No | 0 | Maximum DATAGRAM payload size (0 = disabled) |
| `0x12` | initial_source_connection_id | byte array | No | (none) | Initial SCID (for validation) |
| `0x14` | retry_source_connection_id | byte array | No | (none) | SCID from RETRY packet (if used) |
| `0x16` | stateless_reset_token | 16 bytes | No | (none) | Stateless reset token for this connection |
| `0x20` | anti_censorship_level | VarInt | No | 0 | v2.x: 0=off, 1=obfs, 2=relay, 3=stealth |
| `0x22` | supported_obfs_transforms | byte array | No | (none) | v2.x: Bitmap of supported obfuscation transforms |

**Registry Ranges**:
- `0x00..0x0FFF`: Core v1.0 parameters (even IDs non-critical, odd IDs critical)
- `0x1000..0x1FFF`: Anti-censorship extensions (v2.x)
- `0x2000..0x2FFF`: Universal extensions (v3.x)
- `0x3000..`: Reserved for future use

**CRITICAL (interop): Default behavior**:
- Implementations MUST support all core v1.0 parameters (ID range `0x00..0x1F`).
- If a core parameter is missing and has no default, the connection MUST fail.
- If a critical parameter (odd ID) is unknown, the connection MUST fail.
- If a non-critical parameter (even ID) is unknown, it MUST be silently ignored.

**Value constraints**:
- `max_udp_payload_size`: MUST be >= 1200 (IPv6 minimum MTU) and <= 65527.
- `ack_delay_exponent`: MUST be in range [0, 20]. Values outside this range MUST cause connection failure.
- `active_connection_id_limit`: MUST be >= 2. The value 0 or 1 is invalid and MUST cause connection failure.
- `idle_timeout`: Value 0 means no idle timeout (keep-alive must be application-managed).
- `max_datagram_frame_size`: If set to 0, DATAGRAM frames are disabled. An endpoint that advertised 0 MUST NOT send DATAGRAM frames. If an endpoint receives a DATAGRAM frame when max_datagram_frame_size=0, it MUST silently ignore (drop) the frame and MUST NOT treat it as a connection error. If non-zero, it specifies the maximum payload size in bytes for DATAGRAM frames; frames exceeding this size MUST be dropped.

**Bitmap encoding** (for parameters of type "byte array" representing bitmaps):
- Bitmaps are encoded as a sequence of bytes in **network byte order** (big-endian).
- Bit numbering: **least-significant bit first within each byte**.
- Example: `supported_cc_algorithms = 0x03` means bits 0 and 1 are set (Cubic and BBRv2 supported).

### 5.4. Retry and Address Validation Token

The server MAY require address validation before allocating state.

If the INITIAL contains no valid token, the server MUST reply with RETRY and remain stateless.

Token properties:

- Short-lived (RECOMMENDED max age: 1 hour; anti-replay TTL: 10-30 seconds for 0-RTT).
- Bound to client address (at least IP; binding to port is OPTIONAL).
- Authenticated by server secret (e.g., HMAC).
- Includes an issuance timestamp (or epoch) for expiration.

Token format:

- Token format is implementation-defined.
- Tokens MUST be authenticated and integrity-protected.
- Tokens SHOULD be indistinguishable from random to observers.

#### 5.4.1. Token Mint/Validate (reference algorithm)

Token format (example):

- v: u8
- issued_at_ms: u64
- client_ip: 4 or 16 bytes (v4/v6)
- nonce: [N] bytes
- mac: HMAC-SHA256(secret, v || issued_at_ms || client_ip || nonce)

Validation:

1. Parse and check version.
2. Verify mac.
3. Verify issued_at within max_age.
4. Verify client_ip matches source address.

### 5.5. 0-RTT Early Data (Restricted)

0-RTT is OPTIONAL and MUST be restricted:

- Client MAY send early data only if it has a valid server-issued token.
- Server MUST be stateless until token validation completes.
- Early data MUST be idempotent and MUST NOT cause server-side side effects.

RC1 defines allowed early frames:

- PING
- PATH_CHALLENGE (path probes)

Servers MUST silently drop any other early frames.

0-RTT retransmissions:

- Servers MUST accept and process 0-RTT frames only in the first client INITIAL flight.
- Any 0-RTT frames received in retransmitted INITIAL packets MUST be ignored.

For purposes of this rule, an INITIAL is considered a retransmission if it carries the same client SCID and a
byte-for-byte identical address-validation token that validates successfully.

In particular, servers MUST reject (drop) these frame types if received in 0-RTT:

- STREAM
- DATAGRAM
- NEW_CONNECTION_ID / RETIRE_CONNECTION_ID
- MAX_DATA / MAX_STREAM_DATA / MAX_STREAMS_*
- CC_EVENT
- CONNECTION_CLOSE (other than as part of handshake error handling)

#### 5.5.1. Anti-Replay Filter (required for accepting early data)

If early data is accepted, servers MUST deploy an anti-replay mechanism with TTL 10-30 seconds.

Replay key RECOMMENDED:

- hash = SHA256(token_id || client_nonce || pn0)

Implementation MAY use Bloom or Cuckoo filter or a time-bucketed hash set.
False positives MUST be bounded; target <2% false positives for "censorship detection vs bad network" is not applicable here.

If a replay is detected:

- server MUST NOT process early data (but MAY continue the handshake).

### 5.6. Key Update (1-RTT)

RIFT supports periodic key updates for long-lived sessions.

Mechanism (RC1):

- Key phase is indicated by the Key Phase (KP) bit in the short header.
- Each endpoint maintains "current" and "next" 1-RTT keys derived from the handshake secret.
- To initiate an update, an endpoint switches to the next keys and toggles KP.
- The peer, upon receiving a packet with a different KP that decrypts under "next" keys, MUST transition its receive keys and prepare its own next keys.

**Key derivation for key update** (CRITICAL - interop):

All key update derivations MUST use **HKDF-SHA256** (not BLAKE2s).

The next generation of keys is derived from the current 1-RTT traffic secret:

```
next_secret = HKDF-Expand-SHA256(current_secret, info="rift ku", L=32)
aead_key    = HKDF-Expand-SHA256(next_secret, info="rift aead key", L=32)
aead_iv     = HKDF-Expand-SHA256(next_secret, info="rift aead iv", L=12)
hp_key      = HKDF-Expand-SHA256(next_secret, info="rift hp key", L=32)
```

Where:
- `current_secret` is the **directional** 1-RTT traffic secret (client-to-server or server-to-client, maintained separately)
- Each endpoint maintains two independent traffic secrets (one for sending, one for receiving)
- Key updates are **unilateral**: an endpoint updates its sending keys without coordination
- `info` strings are literal ASCII bytes (no length prefix, no null terminator)
- `L` is the output length in bytes

An endpoint MUST implement limits to prevent infinite key update thrashing.
Recommended limits:

- Minimum packets between updates: 10,000
- Minimum time between updates: 10 seconds

## 6. Frames (Core)

Frames are carried inside encrypted payloads (Section 2.2).
Frames MAY be bundled.

This section defines the RC1 core frame registry.

### 6.1. Common Rules

- Unknown frame types MUST be ignored.
- RC1 defines no generic "critical unknown frame" mechanism.
- Frames that exceed packet limits MUST be dropped.
- Receivers MUST process frames in-order within a packet, but MUST NOT assume reliable delivery.

### 6.2. ACK

Purpose: acknowledge received packets for loss recovery and RTT estimation.

Format (RC1, QUIC-like):

- type: VarInt (value 0x01)
- largest_acked: VarInt
- ack_delay: VarInt
- ack_range_count: VarInt
- first_ack_range: VarInt
- repeated ack ranges (gap, range): VarInt pairs

Algorithm:

- Receiver sends ACK promptly for handshake and P0 traffic.
- ACK delay is bounded by max_ack_delay and encoded with ack_delay_exponent.

**CRITICAL (interop): ACK PN space scoping**

ACK frames acknowledge packets only within the PN space of the packet in which the ACK frame is carried.
Cross-PN-space ACKs are forbidden. For example, an ACK frame carried in a 1-RTT packet MUST NOT acknowledge packets from the INITIAL or HANDSHAKE PN spaces.

Receivers MUST process ACKs only for packets in the same PN space as the packet containing the ACK frame.

**ACK delay interpretation**

ack_delay values in ACK frames carried in INITIAL or HANDSHAKE packets SHOULD be ignored and treated as zero for RTT estimation purposes.
Only ack_delay values in 1-RTT packets are meaningful for RTT calculations.

**CRITICAL (interop): ACK range semantics (normative)**

- ACK ranges are interpreted in descending PN order starting at largest_acked.
- first_ack_range is the number of **additional** contiguous packets acknowledged **before** largest_acked.
- ack_range_count is the number of (gap, range) pairs that follow.

**IMPORTANT: RIFT deviates from QUIC here**:
- In RIFT, first_ack_range represents the count of packets **before** largest_acked (minimum 0).
- first_ack_range = 0 means only largest_acked is acknowledged.
- first_ack_range = 1 means largest_acked and one packet before it are acknowledged (2 packets total).

Decoding algorithm:

1. Let cur = largest_acked.
2. The first acknowledged range is: [cur - first_ack_range, cur] (inclusive).
3. Set cur = cur - first_ack_range - 1 (move to next potential gap).
4. For each of the ack_range_count pairs (gap, range), in order:

```
cur = cur - gap
ack_range = [cur - range, cur] (inclusive)
cur = cur - range - 1
```

**Gap semantics**:
- gap represents the number of unacknowledged packets between ranges.
- gap = 0 means no unacknowledged packets (ranges are contiguous).
- gap = 1 means 1 unacknowledged packet between ranges.
- gap = N means N unacknowledged packets between ranges.

**Range semantics** (applies to both first_ack_range and subsequent range values):
- `first_ack_range` encodes the number of **additional packets before largest_acked**.
- `range` (in subsequent gap-range pairs) encodes the number of **additional packets before cur**.
- Therefore `range = 0` acknowledges exactly **one packet** (cur only).
- `range = N` acknowledges **N+1 packets** (cur and N packets before it).

Constraints:

- first_ack_range MUST be >= 0.
- gap MUST be >= 0.
- range MUST be >= 0.
- Implementations MUST limit ack_range_count to a reasonable value (RECOMMENDED: 64).
- **If ack_range_count exceeds the implementation limit, the entire ACK frame MUST be ignored** (do NOT process partial ranges).
- If decoding produces an acknowledged range that overlaps a prior acknowledged range, the ACK frame MUST be ignored.
- **Adjacent ranges that touch at a boundary (e.g., [96,98] followed by [95,95]) are valid and are NOT considered overlapping.**
- **Monotonicity invariant**: Each newly decoded range MUST satisfy `range_high < previous_range_low`, except for adjacency where `range_high == previous_range_low - 1` is allowed. This ensures ranges are strictly descending without gaps or overlaps.
- If any range would underflow below PN 0, the ACK frame MUST be ignored.
- Receivers MUST NOT acknowledge any PN greater than largest_acked.

**Examples (interop reference)**:

Example 1: Acknowledge only PN 100
```
largest_acked = 100
first_ack_range = 0
ack_range_count = 0
Acknowledged PNs: {100}
```

Example 2: Acknowledge PNs 98, 99, 100
```
largest_acked = 100
first_ack_range = 2
ack_range_count = 0
Acknowledged PNs: {98, 99, 100}
```

Example 3: Acknowledge PNs 100, 98-96, 94-93
```
largest_acked = 100
first_ack_range = 0  (only PN 100)
ack_range_count = 2
gap[0] = 1  (PN 99 missing)
range[0] = 2  (PNs 98, 97, 96)
gap[1] = 1  (PN 95 missing)
range[1] = 1  (PNs 94, 93)

Decoding:
- Range 1: [100, 100] → {100}
- cur = 100 - 0 - 1 = 99
- cur = 99 - 1 = 98
- Range 2: [98-2, 98] = [96, 98] → {96, 97, 98}
- cur = 96 - 1 = 95
- cur = 95 - 1 = 94
- Range 3: [94-1, 94] = [93, 94] → {93, 94}

Acknowledged PNs: {100, 98, 97, 96, 94, 93}
Missing PNs: {99, 95}
```

### 6.3. PING / PONG

Purpose: liveness and RTT sampling.

PING:

- type: VarInt (value 0x10)
- nonce: 8 bytes

PONG:

- type: VarInt (value 0x11)
- nonce: 8 bytes

Receiver MUST respond with PONG echoing nonce.

### 6.4. PATH_CHALLENGE / PATH_RESPONSE

Purpose: path validation and migration safety.

PATH_CHALLENGE:

- type: VarInt (value 0x12)
- data: 8 bytes (cryptographically secure random)

PATH_RESPONSE:

- type: VarInt (value 0x13)
- data: 8 bytes (MUST match PATH_CHALLENGE data exactly)

Receiver MUST respond with PATH_RESPONSE echoing data.

**CRITICAL (interop): Path binding**

The 8-byte data field in PATH_CHALLENGE/PATH_RESPONSE implicitly binds the validation to the 5-tuple (src_ip, src_port, dst_ip, dst_port, protocol) on which the frame is received.

Implementations MUST associate PATH_RESPONSE with the path from which it was received, determined by:
1. The 8-byte data field matching a pending PATH_CHALLENGE
2. The 5-tuple (source/destination IP and port) of the packet carrying the PATH_RESPONSE

PathID (if used internally by an implementation) is an implementation detail and is NOT part of the wire protocol.
Endpoints MUST NOT include PathID in PATH_CHALLENGE or PATH_RESPONSE frames.

### 6.5. STREAM (reliable byte stream)

RC1 defines streams as QUIC-style byte streams with offsets.

STREAM frame:

- type: VarInt (value 0x20)
- flags: u8
  - bit 0: FIN
- stream_id: VarInt
- offset: VarInt
- length: VarInt
- data: [length] bytes

Receiver MUST reassemble by offset and deliver in-order to the application.

### 6.6. MAX_STREAM_DATA / STREAM_DATA_BLOCKED

Purpose: stream-level flow control.

MAX_STREAM_DATA:

- type: VarInt (value 0x21)
- stream_id: VarInt
- max_stream_data: VarInt

STREAM_DATA_BLOCKED:

- type: VarInt (value 0x22)
- stream_id: VarInt
- stream_data_limit: VarInt

### 6.7. MAX_DATA / DATA_BLOCKED

Purpose: connection-level flow control.

MAX_DATA:

- type: VarInt (value 0x23)
- max_data: VarInt

DATA_BLOCKED:

- type: VarInt (value 0x24)
- data_limit: VarInt

### 6.8. MAX_STREAMS / STREAMS_BLOCKED

Purpose: limit the number of concurrently open streams.

MAX_STREAMS_BIDI:

- type: VarInt (value 0x25)
- max_streams: VarInt

STREAMS_BLOCKED_BIDI:

- type: VarInt (value 0x26)
- stream_limit: VarInt

MAX_STREAMS_UNI:

- type: VarInt (value 0x27)
- max_streams: VarInt

STREAMS_BLOCKED_UNI:

- type: VarInt (value 0x28)
- stream_limit: VarInt

### 6.9. DATAGRAM (unreliable)

DATAGRAM frame:

- type: VarInt (value 0x30)
- priority_class: u8 (P0..P3)
- length: VarInt
- data: [length] bytes

DATAGRAM frames are not retransmitted by the transport.
If budget is exceeded, sender SHOULD drop old datagrams according to policy (Section 9).

Fragmentation:

- A DATAGRAM frame MUST fit within a single packet.
- Endpoints MUST NOT fragment a single DATAGRAM across multiple packets.
- If a DATAGRAM cannot fit (e.g., due to MTU/budget), it MUST be dropped.

Unknown priority handling:

- If an endpoint receives an unknown priority_class value, it MUST treat it as P3.
- priority_class MUST be treated as a hint; endpoints MAY remap or ignore it for safety.

### 6.10. NEW_TOKEN

NEW_TOKEN frame:

- type: VarInt (value 0x40)
- token_len: VarInt
- token: [token_len] bytes

Servers SHOULD issue NEW_TOKEN after successful handshake.

### 6.11. CC_EVENT (observability)

CC_EVENT frame provides application-visible feedback without payload inspection.

Format (RC1):

- type: VarInt (value 0x50)
- rtt_ms: VarInt
- rttvar_ms: VarInt
- loss_rate_ppm: VarInt (parts per million)
- jitter_ms: VarInt
- estimated_send_rate_bps: VarInt
- recommended_send_rate_bps: VarInt
- path_id: VarInt (optional; 0 means "default path")

Endpoints SHOULD emit CC_EVENT at a bounded rate (RECOMMENDED: 1-4 Hz).

CC_EVENT restrictions:

- CC_EVENT MUST NOT be sent in 0-RTT.
- Receivers MUST treat CC_EVENT as informational and MUST NOT require it for correctness.

### 6.12. PADDING

PADDING frame increases packet size for traffic shaping and anti-analysis.

Format:

- type: VarInt (value 0x60)
- len: VarInt
- bytes: [len] bytes

Senders SHOULD use bucketized padding in realtime profiles rather than constant-size padding.

Senders MUST set PADDING bytes to 0.
Receivers MUST ignore the contents of PADDING bytes and MUST NOT attempt to interpret them.
Receivers MUST NOT treat non-zero PADDING bytes as an error.

### 6.13. STREAM_META (priority and hints)

STREAM_META associates scheduler hints with a stream.

Format:

- type: VarInt (value 0x61)
- stream_id: VarInt
- priority_class: u8 (0=P0, 1=P1, 2=P2, 3=P3)
- flags: u8
  - bit 0: has_deadline
- if has_deadline:
  - deadline_ms: VarInt (relative deadline for queued data; receiver MAY ignore)

An endpoint that does not implement STREAM_META MUST ignore it.

### 6.14. NEW_CONNECTION_ID / RETIRE_CONNECTION_ID

RIFT supports CID rotation for migration robustness and anti-linkability.

NEW_CONNECTION_ID:

- type: VarInt (value 0x62)
- sequence: VarInt (monotonically increasing per issuer)
- retire_prior_to: VarInt
- cid_len: u8
- cid: [cid_len] bytes

**CRITICAL (interop): CID length constraint**

cid_len MUST be in the range [0, 20] inclusive. Endpoints MUST drop NEW_CONNECTION_ID frames with cid_len > 20.

RETIRE_CONNECTION_ID:

- type: VarInt (value 0x63)
- sequence: VarInt

Rules:

- Endpoints MUST be able to accept NEW_CONNECTION_ID up to active_connection_id_limit.
- An endpoint MUST NOT reuse a retired CID.
- NEW_CONNECTION_ID sequence numbers MUST be strictly increasing and MUST NOT be reused.
- On receiving retire_prior_to, an endpoint SHOULD retire all local CIDs with sequence < retire_prior_to.
- The CID length negotiated during handshake is fixed for the lifetime of the connection (see Section 4.4).
  All CIDs provided via NEW_CONNECTION_ID MUST have the same length as the initial CID.

### 6.15. CONNECTION_CLOSE

CONNECTION_CLOSE terminates a connection with an error code and reason.

Format:

- type: VarInt (value 0x64)
- error_code: VarInt
- frame_type: VarInt (0 if not applicable)
- reason_len: VarInt
- reason: [reason_len] bytes (UTF-8 recommended)

After sending CONNECTION_CLOSE, an endpoint MUST stop sending application data.

CONNECTION_CLOSE transmission:

- CONNECTION_CLOSE MAY be sent in any packet type once the handshake completes.
- During the handshake, CONNECTION_CLOSE SHOULD be sent in a HANDSHAKE packet if possible; otherwise in an INITIAL packet.

Closing behavior:

- The sender SHOULD retransmit CONNECTION_CLOSE on PTO at most 3 times (best-effort).
- After sending or receiving CONNECTION_CLOSE, an endpoint SHOULD enter a DRAINING state and
  ignore all subsequent packets for a draining period of 3*PTO or 2 seconds, whichever is larger.
- Implementations MAY drop connection state immediately after the draining period.

Stateless reset:

- Stateless reset is out of scope for RC1.

#### 6.15.1. Error Code Registry (RC1)

Error codes are carried in the CONNECTION_CLOSE frame and indicate the reason for connection termination.

| Error Code | Name | Description | Recommended Action |
|------------|------|-------------|-------------------|
| `0x00` | NO_ERROR | Graceful shutdown with no error | Clean close |
| `0x01` | INTERNAL_ERROR | Implementation bug or unexpected condition | Log and report |
| `0x02` | CONNECTION_REFUSED | Server refused connection (policy, capacity) | Retry with backoff |
| `0x03` | FLOW_CONTROL_ERROR | Flow control limits violated | Fix sender logic |
| `0x04` | STREAM_LIMIT_ERROR | Stream ID or stream count limit violated | Fix sender logic |
| `0x05` | STREAM_STATE_ERROR | Frame received in invalid stream state | Fix sender logic |
| `0x06` | FINAL_SIZE_ERROR | Stream final size changed or inconsistent | Fix sender logic |
| `0x07` | FRAME_ENCODING_ERROR | Malformed frame detected | Drop packet |
| `0x08` | TRANSPORT_PARAMETER_ERROR | Invalid or inconsistent transport parameter | Fail handshake |
| `0x09` | CONNECTION_ID_LIMIT_ERROR | Too many Connection IDs provided | Fix sender logic |
| `0x0a` | PROTOCOL_VIOLATION | Generic protocol violation not covered by specific codes | Fix sender logic |
| `0x0b` | INVALID_TOKEN | Address validation token invalid or expired | Retry handshake |
| `0x0c` | APPLICATION_ERROR | Application-specific error | Application-defined |
| `0x0d` | CRYPTO_ERROR | Cryptographic operation failed | Check keys/config |
| `0x0e` | CRYPTO_BUFFER_EXCEEDED | Too much unprocessed crypto data | Fix receiver buffering |
| `0x0f` | KEY_UPDATE_ERROR | Key update protocol violation | Fix key rotation |
| `0x10` | AEAD_LIMIT_REACHED | AEAD integrity limit exceeded | Rotate keys |
| `0x11` | NO_VIABLE_PATH | All paths failed validation or became unusable | Check network |
| `0x12` | INVALID_FRAME_BUNDLE | FRAME_BUNDLE is malformed (trailing bytes, invalid inner frame) | Fix sender logic |
| `0x100` | CRYPTO_HANDSHAKE_FAILED | Noise handshake failed (catch-all) | Check server key |
| `0x101` | CRYPTO_NO_SUPPORT | Unsupported crypto algorithm or version | Update implementation |
| `0x102` | CRYPTO_INTERNAL | Internal crypto library error | Check crypto backend |

**Error Code Ranges**:
- `0x00..0xFF`: Core transport errors (v1.0)
- `0x100..0x1FF`: Cryptographic and handshake errors
- `0x200..0x2FF`: Anti-censorship errors (v2.x)
- `0x300..0x3FF`: Application-defined errors
- `0x400..`: Reserved for future use

**CRITICAL (interop): Error handling rules**:
- Implementations MUST recognize all core error codes (`0x00..0x1FF`).
- Unknown error codes SHOULD be treated as `INTERNAL_ERROR` for logging purposes.
- Error codes in the range `0x300..0x3FF` are application-defined and MAY have custom semantics.
- The `frame_type` field in CONNECTION_CLOSE MUST be set to the frame type that caused the error, or `0x00` if not applicable.
- The `reason` string SHOULD be human-readable UTF-8 but MUST NOT be relied upon for programmatic error handling.

**Closing state machine**:
1. **CLOSING**: Local endpoint sent CONNECTION_CLOSE
   - MAY retransmit CONNECTION_CLOSE on PTO (max 3 times)
   - MUST ignore all incoming packets except CONNECTION_CLOSE
   - MUST NOT send new application data
   - Duration: 3*PTO or 2 seconds, whichever is larger

2. **DRAINING**: Local endpoint received CONNECTION_CLOSE
   - MUST NOT send any packets (including CONNECTION_CLOSE)
   - MUST silently ignore all incoming packets
   - Duration: 3*PTO or 2 seconds, whichever is larger

3. **CLOSED**: After draining period expires
   - Connection state MAY be discarded immediately
   - Any packets received MUST be silently dropped

## 7. Loss Recovery and Timers

RIFT loss recovery is ACK-based.

RC1 requires:

- packet tracking per PN space (sent time, size, acked, in-flight)
- RTT estimation (smoothed RTT, rttvar)
- PTO (probe timeout) for re-transmission of reliable frames

Reference algorithm is QUIC-like:

- On ACK: update RTT, mark acked, detect losses using time threshold.
- On loss: retransmit STREAM data and control frames; do not retransmit DATAGRAM.
- PTO: schedule probe when no ACK arrives within PTO = smoothed_rtt + max(4*rttvar, kGranularity) + max_ack_delay.

Invariant:

- DATAGRAM frames MUST NOT be retransmitted.

**Multipath loss recovery**:

- **PTO timers MUST be maintained per validated path.**
- Loss detection decisions for packets sent on a path MUST use RTT estimates (smoothed_rtt, rttvar) of that path.
- Each path maintains its own PTO timer: `PTO_path = smoothed_rtt_path + max(4*rttvar_path, kGranularity) + max_ack_delay`.
- Probe packets triggered by a path's PTO SHOULD be sent on that same path (unless the path is no longer viable).

## 8. Congestion Control and Pacing

RIFT supports at least:

- CUBIC (baseline)
- BBRv2 (target default)

Endpoints MUST implement pacing.
Congestion control MUST operate on bytes_in_flight and acked/lost signals.

Scheduler interacts with CC by allocating a per-tick send budget; when budget is exhausted, lower-priority queued data is dropped or deferred.

Multipath congestion control:

- Each validated path MUST maintain independent congestion control state (cwnd, pacing, loss/RTT samples).
- The scheduler operates over an aggregate budget derived from the active path set, but MUST respect each path's pacing and cwnd.
- An implementation MUST NOT exceed the cwnd of any individual path when sending on that path. Aggregation of budgets MUST NOT cause per-path pacing or cwnd limits to be violated.
- Loss attribution for CC purposes MUST be path-scoped even if PN space is connection-scoped.
- Senders MUST record the sending path_id for each transmitted packet number (PN).
- When a packet is declared lost, that loss signal MUST be attributed to the path_id on which the packet was sent.
- ACK frames MAY be sent on any validated path; receivers MUST accept ACKs regardless of the receiving path.
- ACK processing MUST be independent of the path on which the ACK frame is received.
- Reordering across paths MUST be tolerated, and PN reconstruction MUST be performed solely based on the global PN space, not per-path ordering.

## 9. QoS Scheduler and Priority Classes

RIFT defines four priority classes:

- P0: audio/signaling (deadline-oriented, drop-oldest)
- P1: video/interactive realtime (deadline + adaptive)
- P2: interactive data (reliable, not latency-critical)
- P3: background (bulk)

Each outgoing unit is assigned:

- class (P0..P3)
- deadline (optional)
- size
- retransmittable flag (STREAM/control) vs non-retransmittable (DATAGRAM)

### 9.1. Scheduling Rules (RC1)

- P0 MUST be protected from starvation by P1..P3.
- P2/P3 MUST get some bandwidth in stable networks (anti-starvation).
- When budget is tight:
  - DATAGRAM: drop old frames first (per-class policy).
  - STREAM: retransmit important control and in-flight stream ranges with priority.

Reference scheduling loop (non-normative):

```
on_tick(dt_ms):
  budget_bytes = pacing_rate_bps * dt_ms / 8000
  budget_bytes = min(budget_bytes, cwnd_bytes - bytes_in_flight)

  while budget_bytes > 0:
    item = pick_next_item(P0..P3 queues, deadlines, weights)
    if item == none: break

    if item.kind == DATAGRAM and item.is_expired(now):
      drop(item); continue

    if item.size > budget_bytes:
      if item.kind == DATAGRAM and item.class in {P1,P2,P3}:
        // allow dropping rather than fragmenting
        drop(item); continue
      else:
        break

    send(item)
    budget_bytes -= item.size
```

pick_next_item SHOULD implement:

- strict preference for P0 if any P0 item is near deadline
- weighted round-robin between P1/P2/P3 when P0 is idle
- anti-starvation by guaranteeing a minimum service share for P2/P3 in stable networks

Abuse resistance:

- Implementations SHOULD enforce per-peer and per-class rate limits to prevent priority inversion attacks.
- Implementations SHOULD cap P0/P1 admission (bytes/s or packets/s) and drop excess to protect overall system stability.

### 9.2. Programmable Policy (optional)

RC1 defines a policy interface (not necessarily a bytecode VM yet):

Inputs:

- RTT, rttvar, loss_rate, jitter
- estimated_rate, cwnd, pacing_rate
- per-path health, active path
- censorship confidence (v2.x)

Outputs:

- enable/disable duplication window per class
- select FEC scheme/overhead per class
- class weights and drop thresholds

Policy MUST NOT violate CC invariants (no sending above pacing budget).

## 10. Multipath, Migration, and Keep-Alive

### 10.1. Path Validation

Before using a new path for non-probing traffic, an endpoint MUST validate it:

1. Send PATH_CHALLENGE on the new path.
2. Receive PATH_RESPONSE with matching data.

Only after validation MAY the endpoint migrate application traffic to that path.

### 10.2. NAT Rebinding

Servers MUST tolerate rebinding (client source port/IP changes) without re-handshake if:

- CID matches an active connection, and
- path validation succeeds.

### 10.3. Multipath Modes

RC1 defines modes:

- Standby: keep a secondary path alive with infrequent probes.
- Active-backup: switch to secondary on degradation.
- Duplication window: duplicate selected P0 frames across two paths for a short window.

Duplication MUST be bounded to prevent traffic blow-up.

Path scoring (non-normative, recommended):

- Maintain per-path EWMA metrics: rtt_ms, loss_rate, jitter_ms, blackout_count.
- Compute score:

```
score = w_rtt * norm(rtt_ms) + w_loss * norm(loss_rate) + w_jitter * norm(jitter_ms)
```

- Active-backup switch condition SHOULD trigger when:
  - score(active) exceeds score(backup) by a threshold for N consecutive samples, or
  - active path has blackout for > X ms.

### 10.4. Adaptive Keep-Alive

Endpoints SHOULD discover NAT timeout and send keep-alives minimally.
Keep-alive MUST NOT be constant-rate by default in realtime profile.

## 11. Forward Error Correction (FEC)

FEC is OPTIONAL and feature-gated.

Schemes:

- XOR parity (low overhead, e.g., 10+1)
- Reed-Solomon (higher overhead, for worse loss/jitter)

Policy thresholds (recommended):

- loss > 1%: enable XOR for P0/P1 datagrams
- loss > 5% or jitter > 30ms: enable RS in short blocks

FEC MUST NOT increase P0 end-to-end latency; prefer dropping video to delaying audio.

Scope:

- FEC MUST be applied only to DATAGRAM traffic.
- FEC MUST NOT be used for STREAM data.

## 12. Observability

RIFT exposes:

- CC_EVENT frame (Section 6.11)
- state events (connect, retry, key update, migrate, path degraded)

Observability MUST NOT require payload decryption by intermediaries.
Telemetry MUST be opt-in and privacy-preserving (no PII, no content).

## 13. Anti-Censorship Extensions (v2.x)

This section defines optional modules that do not change core behavior when disabled.

### 13.1. Obfuscation Layer (RIFT-OBF)

RIFT-OBF is a transform applied below the RIFT packet layer.
Transforms:

- obfs4 (v1.5)
- tls-mimic (v2.0)
- shadowsocks-compatible (v2.0)

Negotiation:

- client advertises supported transforms via transport parameters.
- server selects transform (or none) based on anti_censorship_level.

Downgrade resistance:

- Transform negotiation is authenticated as part of the handshake transport parameters.
- On-path downgrade attempts (e.g., forcing "none") MUST be detected.

Integrity:

- Anti-censorship layers MUST NOT modify encrypted RIFT payloads.
- Obfuscation/fallback layers operate below the RIFT packet layer (wrapping, framing, transport), not by rewriting ciphertext.

### 13.2. Fallback Transports (RIFT-FALL)

Fallback chain (recommended):

- UDP -> TCP -> WebSocket

TCP wrapper framing (RC1):

- length: VarInt
- packet_bytes: [length] bytes (a complete RIFT UDP packet encoding)

WebSocket:

- binary frames carrying the same TCP wrapper framing, optionally over TLS.

### 13.3. Relay Infrastructure (RIFT-RELAY)

Single-hop relay forwards packets between client and origin server.

Security:

- Relay MUST NOT require access to plaintext.
- Relay MAY terminate an outer obfuscation layer, but MUST preserve end-to-end crypto.

Access control:

- Proof-of-Work (PoW) MAY be required before allowing relay resources.

PoW reference puzzle:

- challenge: 32 bytes
- difficulty: u32
- TTL: 60 seconds
- solution: nonce such that u32_be(first 4 bytes of BLAKE2s(challenge || nonce)) <= target

Definitions:

- Interpret the first 4 bytes of BLAKE2s output (bytes 0..3) as an unsigned 32-bit integer in big-endian order.
- target = floor(2^32 / difficulty), where difficulty >= 1.
- A relay MUST reject puzzles with difficulty == 0.

### 13.4. Censorship Detection (RIFT-DETECT)

Detection uses a confidence score computed from probes and traffic patterns.

Reference logic (non-normative):

1. If handshake timeouts >= 3, run probes:
  - ICMP ping to server
  - TCP connect to fallback port
  - DNS resolution
2. Determine likely block type (port/ip/dpi/udp).
3. If confidence >= 0.8, enable obfuscation or escalate level.

False positives SHOULD be <2% in production datasets.

### 13.5. Signed Transform Manifests

To update obfuscation parameters without client release:

- Manifest is fetched over HTTPS (possibly via CDN).
- Manifest is signed by Ed25519 key pinned in the client.
- Client MUST validate signature and validity window before applying.

## 14. Universal Extensions (v2.5-v3.x, non-wire)

Universal mode adds system-wide behaviors above core transport.
These features MUST NOT change core wire format.

### 14.1. Proxy/Adapters (RIFT-ADAPT)

Adapters provide compatibility for existing applications:

- SOCKS5 proxy (user-space, no privileges)
- HTTP CONNECT proxy (user-space)
- UDP forwarders for games/legacy protocols (user-space)
- Transparent proxy (OS hooks) is OPTIONAL and platform-dependent

Adapters feed "host hints" (Host/SNI/domain) into the classifier.

### 14.2. Virtual Interface (RIFT-VIF)

TUN mode (platform-gated):

- reads IP packets from a virtual interface
- classifies and encapsulates them into RIFT streams/datagrams
- enforces routing policy (split/full tunnel)

Leak prevention and kill-switch are REQUIRED in "full-tunnel desktop" profile.

### 14.3. Traffic Classification (RIFT-CLASS)

RC1 classifier MVP:

- Port-based rules -> priority class
- Hostname suffix rules (proxy-mode) -> priority class

Classification MUST be safe-by-default:

- P0/P1 protection must not be compromised by misclassification.
- P3 bulk SHOULD be throttled when realtime is active.

ML-based classification is explicitly research-only and MUST NOT be a hard dependency.

## 15. Security Considerations (non-exhaustive)

- Replay: 0-RTT early data is replayable; restrict to idempotent frames and require anti-replay filter.
- DoS: servers MUST remain stateless until address validation.
- Ossification: header protection and greasing are REQUIRED.
- Privacy: observability should not leak content; telemetry must be opt-in and coarse-grained.
- Relay risk: single-hop relay can correlate client IP with server identity; multi-hop is required for high-anonymity modes (v2.1+).

## Appendix A. Frame Registry (RC1)

Frame Type is a VarInt.
This registry is normative for RC1.

Frame types listed in this appendix are shown in their minimal VarInt encoding.

Registry ranges:

- 0x0000..0x3FFF: standardized frames (VarInt 1-2 bytes; recommended interop set)
- 0x4000..0x7FFF: experimental (requires negotiation; may change)
- 0x8000..: private use (no interoperability expectations)

- 0x00: FRAME_BUNDLE
- 0x01: ACK
- 0x10: PING
- 0x11: PONG
- 0x12: PATH_CHALLENGE
- 0x13: PATH_RESPONSE
- 0x20: STREAM
- 0x21: MAX_STREAM_DATA
- 0x22: STREAM_DATA_BLOCKED
- 0x23: MAX_DATA
- 0x24: DATA_BLOCKED
- 0x25: MAX_STREAMS_BIDI
- 0x26: STREAMS_BLOCKED_BIDI
- 0x27: MAX_STREAMS_UNI
- 0x28: STREAMS_BLOCKED_UNI
- 0x30: DATAGRAM
- 0x40: NEW_TOKEN
- 0x50: CC_EVENT
- 0x60: PADDING
- 0x61: STREAM_META
- 0x62: NEW_CONNECTION_ID
- 0x63: RETIRE_CONNECTION_ID
- 0x64: CONNECTION_CLOSE

## Appendix P. Bootstrap Prototype Mapping (Informative)

This appendix documents the current repository bootstrap wire (`rift-rs/crates/rift-wire`) to
avoid confusion between the target RC1 wire and the prototype.

### P.1. Prototype Outer Packet Types (1 byte)

- 0x01: TYPE_HANDSHAKE_1
- 0x02: TYPE_HANDSHAKE_2
- 0x03: TYPE_DATA
- 0x04: TYPE_RETRY

Packet header in the prototype is:

- type:u8 || conn_id:u64 || pn:u64 || len:u16 || payload:[len]

### P.2. Prototype Frame Types (1 byte)

- 0x00: FRAME_BUNDLE (container, u16-length entries)
- 0x10: PATH_CHALLENGE
- 0x11: PATH_RESPONSE
- 0x12: PING
- 0x13: PONG
- 0x20: APP (raw bytes, testing only)
- 0x30: STREAM_DATA (message-based, seq + bytes)
- 0x31: STREAM_ACK (ack_max + 64-bit mask)
- 0x40: NEW_TOKEN

## Appendix B. Connection State Machine (high level)

Client:

1. send INITIAL (token optional)
2. on RETRY: store token, resend INITIAL
3. on HANDSHAKE: derive 1-RTT keys, enter ESTABLISHED

Server:

1. on INITIAL without valid token: send RETRY (stateless)
2. on INITIAL with valid token: complete Noise, send HANDSHAKE, enter ESTABLISHED
3. issue NEW_TOKEN after handshake

## Appendix C. Interoperability Test Vectors (RC1)

This appendix provides golden test vectors for critical interoperability points in RIFT RC1.
All values are in hexadecimal unless otherwise noted.

### C.1. Header Protection Removal

**NOTE**: The following test vectors are **illustrative** and demonstrate the algorithm steps. The mask values shown are **example values** for demonstration purposes. For fully computable golden vectors with verifiable cryptographic outputs, see implementation test suites.

**Test Vector 1: Short Header HP Removal (Illustrative)**

Input (protected packet bytes):
```
43 ab cd ef 12 34 56 78 90 01 23 45 67 89 ab cd ef  // Header (protected)
a1 b2 c3 d4 e5 f6 a7 b8 c9 d0 e1 f2 a3 b4 c5 d6  // Payload (encrypted, first 16 bytes shown)
e7 f8 09 1a 2b 3c 4d 5e ...                      // (remaining payload)
```

Assumptions:
- First byte: `0x43` (Short Header, PN length = 4 bytes based on bits 0-1)
- DCID length: 8 bytes (known from handshake)
- DCID: `ab cd ef 12 34 56 78 90`
- Protected PN bytes: `01 23 45 67` (4 bytes)
- Sample starts at byte 20 (after header + 4 bytes into payload)

HP key (ChaCha20):
```
1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b
```

Sample (16 bytes starting at byte 20):
```
a1 b2 c3 d4 e5 f6 a7 b8 c9 d0 e1 f2 a3 b4 c5 d6
```

HP mask computation (per Section 4.5.3.1):
```
counter = u32_le(sample[0..3]) = u32_le(a1 b2 c3 d4) = 0xd4c3b2a1
nonce = sample[4..15] = e5 f6 a7 b8 c9 d0 e1 f2 a3 b4 c5 d6
mask_stream = ChaCha20(key=hp_key, counter=counter, nonce=nonce)
mask = first 5 bytes of mask_stream = aa bb cc dd ee (example value)
```

Unprotected first byte:
```
first_byte = 0x43 XOR (0xaa AND 0x1f) = 0x43 XOR 0x0a = 0x49
```

Unprotected PN bytes:
```
pn[0] = 0x01 XOR 0xbb = 0xba
pn[1] = 0x23 XOR 0xcc = 0xef
pn[2] = 0x45 XOR 0xdd = 0x98
pn[3] = 0x67 XOR 0xee = 0x89
```

Expected output (unprotected header):
```
First byte: 0x49
DCID: ab cd ef 12 34 56 78 90
Unprotected PN bytes: ba ef 98 89
Full reconstructed PN: (depends on largest_pn, see C.4)
```

### C.2. AEAD Associated Data (AD) Construction

**Test Vector 2: Short Header 1-RTT Packet AD**

Unprotected header bytes (after HP removal):
```
49 ab cd ef 12 34 56 78 90 ba ef 98 89
```

Breakdown:
- First byte: `0x49`
- DCID (8 bytes): `ab cd ef 12 34 56 78 90`
- PN bytes (4 bytes): `ba ef 98 89`

**Associated Data** (exact header bytes as they appear after HP removal):
```
AD = 49 ab cd ef 12 34 56 78 90 ba ef 98 89
```

AD length: 13 bytes

This AD is passed to ChaCha20-Poly1305 AEAD decryption.

**Test Vector 3: Long Header INITIAL Packet AD**

Unprotected header bytes (after HP removal):
```
c0 00 00 00 01 08 ab cd ef 12 34 56 78 90 08 fe dc ba 09 87 65 43 21 00 00 12 ba
```

Breakdown:
- First byte: `0xc0` (Long Header, INITIAL, PN length = 1 from bits 0-1)
- Version: `0x00000001` (VarInt, 4 bytes)
- DCID length: `0x08` (8 bytes)
- DCID: `ab cd ef 12 34 56 78 90`
- SCID length: `0x08` (8 bytes)
- SCID: `fe dc ba 09 87 65 43 21`
- Token length: `0x00` (VarInt, no token)
- Payload length: `0x0012` (VarInt, 18 bytes)
- PN bytes: `0xba` (1 byte, PN length = 1)

**Associated Data** (entire unprotected header up to but not including encrypted payload):
```
AD = c0 00 00 00 01 08 ab cd ef 12 34 56 78 90 08 fe dc ba 09 87 65 43 21 00 00 12 ba
```

AD length: 27 bytes

This AD is passed to ChaCha20-Poly1305 AEAD decryption for the INITIAL packet.

### C.3. AEAD Nonce Construction

**Test Vector 4: 1-RTT Packet Nonce**

Assumptions:
- Reconstructed PN: `0x00000000babe1234` (64-bit)
- PN space: 1-RTT
- Traffic secret derived from Noise handshake (simplified for test):

```
traffic_secret_0 = 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
```

Derive IV (HKDF-Expand-Label from traffic_secret, label="rift iv", length=12):
```
iv = aa bb cc dd ee ff 00 11 22 33 44 55  // 12 bytes
```

Nonce construction:
```
pn_bytes = [0x00, 0x00, 0x00, 0x00, 0xba, 0xbe, 0x12, 0x34]  // 8 bytes (left-padded)
nonce = iv XOR (0x00000000 || pn_bytes)
nonce[0..3] = iv[0..3] XOR 0x00000000 = aa bb cc dd
nonce[4..11] = iv[4..11] XOR pn_bytes = (ee ff 00 11 22 33 44 55) XOR (00 00 00 00 ba be 12 34)
nonce[4..11] = ee ff 00 11 d8 8d 56 61
```

**Final nonce**:
```
aa bb cc dd ee ff 00 11 d8 8d 56 61  // 12 bytes
```

This nonce is used with ChaCha20-Poly1305 AEAD.

### C.4. Packet Number Reconstruction

**Test Vector 5: PN Reconstruction**

Scenario 1: Normal case
```
largest_pn = 1000
truncated_pn_bytes = 0x03ed  // 2 bytes
pn_len = 2 bytes

Expected reconstructed PN: 1005
```

Algorithm:
```
pn_win = 1 << (pn_len * 8) = 1 << 16 = 65536
pn_hwin = pn_win / 2 = 32768
expected_pn = largest_pn + 1 = 1001
candidate = expected_pn - (expected_pn % pn_win) + truncated_pn = 1001 - 1001 + 1005 = 1005

// Check if candidate is within [expected_pn - pn_hwin, expected_pn + pn_hwin]
expected_pn - pn_hwin = 1001 - 32768 = -31767 (clamp to 0)
expected_pn + pn_hwin = 1001 + 32768 = 33769

candidate (1005) is within [0, 33769], so reconstructed PN = 1005
```

Scenario 2: Wraparound case
```
largest_pn = 65530
truncated_pn_bytes = 0x0005  // 2 bytes (value 5)
pn_len = 2 bytes

Expected reconstructed PN: 65541
```

Algorithm:
```
pn_win = 65536
pn_hwin = 32768
expected_pn = 65531
candidate = 65531 - 65531 + 5 = 5

// 5 is NOT within [65531 - 32768, 65531 + 32768] = [32763, 98299]
// Add pn_win: candidate = 5 + 65536 = 65541
// 65541 is within range, so reconstructed PN = 65541
```

### C.5. ACK Frame Decoding

**Test Vector 6: ACK Frame with Multiple Ranges**

ACK frame bytes (after frame type):
```
Type: 0x01 (ACK)
largest_acked: 0x64 (100)
ack_delay: 0x0a (10)
ack_range_count: 0x02 (2 ranges)
first_ack_range: 0x00 (0 additional packets before largest_acked)

Range 0:
  gap: 0x01 (1 unacked packet)
  range: 0x02 (3 packets in this range)

Range 1:
  gap: 0x01 (1 unacked packet)
  range: 0x01 (2 packets in this range)
```

Decoding:
```
1. cur = 100
2. First range: [100 - 0, 100] = [100, 100] → {100}
3. cur = 100 - 0 - 1 = 99
4. Process Range 0:
   cur = 99 - 1 = 98
   ack_range = [98 - 2, 98] = [96, 98] → {96, 97, 98}
   cur = 96 - 1 = 95
5. Process Range 1:
   cur = 95 - 1 = 94
   ack_range = [94 - 1, 94] = [93, 94] → {93, 94}
   cur = 93 - 1 = 92
```

**Acknowledged PNs**: {100, 98, 97, 96, 94, 93}
**Missing PNs**: {99, 95}

### C.6. Interoperability Test Plan

Implementations MUST pass the following interop tests to claim RC1 conformance:

**Handshake Tests**:
1. Complete INITIAL → HANDSHAKE → 1-RTT handshake
2. Handle RETRY correctly (token round-trip)
3. Reject invalid tokens
4. Process transport parameters correctly
5. Derive correct keys from Noise IK pattern

**Packet Processing Tests**:
6. Remove Header Protection correctly (both Long and Short headers)
7. Construct AEAD AD correctly
8. Construct AEAD nonce correctly
9. Decrypt packets successfully
10. Reconstruct packet numbers correctly (including wraparound)

**Frame Processing Tests**:
11. Decode ACK frames with multiple ranges
12. Respect ACK PN space scoping (no cross-PN-space ACKs)
13. Process STREAM frames (flow control, reassembly)
14. Process DATAGRAM frames
15. Process PATH_CHALLENGE/PATH_RESPONSE correctly

**Error Handling Tests**:
16. Send CONNECTION_CLOSE with correct error code
17. Enter CLOSING/DRAINING states correctly
18. Reject packets with invalid CID length
19. Reject unknown critical transport parameters

**Multipath Tests**:
20. Validate paths using PATH_CHALLENGE/PATH_RESPONSE
21. Bind validation to 5-tuple, not PathID
22. Handle connection migration

Implementations passing all 22 tests are considered **RC1 conformant**.
