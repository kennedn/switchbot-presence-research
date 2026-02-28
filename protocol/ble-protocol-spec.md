# Device BLE Protocol – General Specification

## 1. Overview

This document describes the BLE framing structure and encryption model used by the device.

The protocol consists of:
- A plaintext wrapper
- An AES-CTR encrypted payload
- A device-provided IV per transaction

---

# 2. BLE Wrapper Format

All encrypted commands are transmitted using the following structure:

| Offset | Length | Field       | Example | Description |
|--------|--------|------------|---------|------------|
| 0      | 1 byte | Header     | 57      | Constant frame identifier |
| 1      | 1 byte | KeyID      | aa      | Cloud account key slot |
| 2      | 2 bytes| IV Prefix  | 8b5c    | First 2 bytes of IV |
| 4      | N bytes| Ciphertext | d18ad44d50 | AES-CTR encrypted payload |

---

## 3. Example TX Frame

```

57aa8b5cd18ad44d50

```

| Segment      | Value        |
|--------------|-------------|
| Header       | 57 |
| KeyID        | aa |
| IV Prefix    | 8b5c |
| Ciphertext   | d18ad44d50 |

---

# 4. Encryption Specification

| Property | Value |
|----------|--------|
| Algorithm | AES |
| Mode | CTR |
| Padding | NoPadding |
| Key Length | 16 bytes |

---

## Example Key

```

aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

```

---

## Example IV (from device)

```

8b5c3fcc8347d2c419a3d9586605acd4

```

| Field | Value |
|--------|--------|
| Full IV | 8b5c3fcc8347d2c419a3d9586605acd4 |
| IV Prefix (used in wrapper) | 8b5c |

---

# 5. IV Request Flow

## 5.1 IV Request (Unencrypted)

```

570000000f2103aa

```

| Offset | Length | Field | Value | Description |
|--------|--------|--------|--------|------------|
| 0 | 1 | Header | 57 | Frame identifier |
| 1 | 1 | KeyID slot | 00 | Empty for IV request |
| 2 | 2 | IV prefix slot | 0000 | Empty for IV request |
| 4 | 3 | Opcode | 0f2103 | Unencrypted IV request opcode |
| 7 | 1 | KeyID | aa | Account key slot |

---

## 5.2 IV Response

```

010000008b5c3fcc8347d2c419a3d9586605acd4

```

| Offset | Length | Field | Value | Description |
|--------|--------|--------|--------|------------|
| 0 | 1 | Status | 01 | Success |
| 1 | 1 | KeyID slot | 00 | Reserved |
| 2 | 2 | IV prefix slot | 0000 | Reserved |
| 4 | 16 | IV | 8b5c3fcc8347d2c419a3d9586605acd4 | Full IV for AES-CTR |

---

# 6. ACK Format

```

01aa8b5c

```

| Offset | Length | Field | Value | Description |
|--------|--------|--------|--------|------------|
| 0 | 1 | Status | 01 | Success |
| 1 | 1 | KeyID | aa | Echoed KeyID |
| 2 | 2 | IV Prefix | 8b5c | Echoed IV prefix |
```

