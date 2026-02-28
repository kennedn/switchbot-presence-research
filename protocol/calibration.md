# Detection Sensitivity – Calibration & Polling Flow

## Overview

This flow is triggered when entering the **Detection Sensitivity calibration dialog**.

Observed behavior consists of:

1. Repeated IV acquisition
2. Short probe-style encrypted exchanges
3. Structured indexed table reads
4. No observed commit/write operations

The flow appears read-dominant and structured.

---

# Phase 1 – Initial Polling / Probe Behavior

Before structured table iteration begins, the app performs repeated short encrypted exchanges.

These appear to:

- Confirm device readiness
- Retrieve small state values
- Possibly obtain metadata before table extraction

---

## 1.1 IV Acquisition (Repeated Before Each Transaction)

### App → Device (Unencrypted)

| Offset | Bytes | Description |
|--------|-------|------------|
| 0 | 57 | Protocol header |
| 1 | 00 | KeyID slot (empty) |
| 2–3 | 0000 | IV prefix slot (empty) |
| 4–6 | 0f2103 | Unencrypted opcode |
| 7 | b9 | KeyID |

Example:
```
570000000f2103b9
```

---

### Device → App

| Offset | Bytes | Description |
|--------|-------|------------|
| 0 | 01 | Status (01 = success) |
| 1 | 00 | KeyID slot (unused) |
| 2–3 | 0000 | IV prefix slot (unused) |
| 4–19 | 16 bytes | Full IV for AES-CTR |

Example:
```
010000001ed1f6f6cf519226b1ecdd9b7441f534
```

This IV is used immediately for a single AES-CTR encrypted transaction.

---

## 1.2 Short Encrypted Probe Transactions

Observed plaintext request examples:

| Plaintext | Description (Hypothesized) |
|-----------|----------------------------|
| 34c5 | Small state query |
| 0f7701 | Short opcode probe |
| 35c4 | Alternate small query |

Observed decrypted responses:

| Plaintext Response | Interpretation |
|-------------------|---------------|
| 0002 | Likely small integer status |
| 0103 | Small structured return |
| 0002 | Repeated consistent value |

### Observed Pattern

| Behavior | Detail |
|----------|--------|
| Very short payloads | 2–3 bytes |
| Repeated | Same request returns same value |
| No index progression | Not part of table iteration |
| No follow-up write | Appears informational |

This phase appears to be **status polling or capability discovery**.

---

# Phase 2 – Structured Table Read Phase

After polling stabilizes, structured indexed reads begin.

---

## 2.1 Encrypted Request Structure

After IV acquisition:

| Offset | Bytes | Description |
|--------|-------|------------|
| 0 | 57 | Header |
| 1 | b9 | KeyID |
| 2–3 | IV[0–1] | First two bytes of IV |
| 4–N | Ciphertext | AES-CTR encrypted payload |

---

## 2.2 Plaintext Request Pattern

Decrypted payload structure:

| Offset | Bytes | Description |
|--------|-------|------------|
| 0–1 | 0f77 | Calibration opcode |
| 2 | 03 | Table group |
| 3 | Subtable ID | Observed: 01, 03 |
| 4 | Row index | 00–0d observed |

Example requests:

| Plaintext | Meaning |
|-----------|--------|
| 0f77030100 | Read table 03, subtable 01, row 00 |
| 0f7703010d | Read table 03, subtable 01, row 13 |
| 0f77030300 | Read table 03, subtable 03, row 00 |

---

## 2.3 Plaintext Response Structure

Decrypted response format:

| Offset | Bytes | Description |
|--------|-------|------------|
| 0 | Row index | Echo/index |
| 1–2 | Value 1 | uint16 (LE) |
| 3–4 | Value 2 | uint16 |
| 5–6 | Value 3 | uint16 |
| 7–8 | Value 4 | uint16 |
| 9–10 | Value 5 | uint16 |
| 11–12 | Value 6 | uint16 |
| 13–14 | Value 7 | uint16 |

Example decrypted response:

```
00017b0197018801bf01c0016c0170
```

Decoded:

| Field | Hex | Decimal |
|-------|-----|---------|
| Row | 00 | 0 |
| V1 | 017b | 379 |
| V2 | 0197 | 407 |
| V3 | 0188 | 392 |
| V4 | 01bf | 447 |
| V5 | 01c0 | 448 |
| V6 | 016c | 364 |
| V7 | 0170 | 368 |

---

# Phase 3 – Observed Structural Characteristics

| Characteristic | Observation |
|----------------|------------|
| Read-only | No write/commit opcodes observed |
| Indexed iteration | Row index increments sequentially |
| Multiple subtables | Subtable 01 and 03 observed |
| Fixed-width rows | 1 byte index + 7 × uint16 values |
| Repeated IV fetch | Each transaction preceded by IV acquisition |
| Short pre-phase probes | Small payload polling before structured reads |

---

# Behavioral Interpretation

| Phase | Likely Purpose |
|-------|---------------|
| Initial polling | Device readiness / status check |
| Indexed reads | Calibration LUT extraction |
| Subtable variation | Multiple calibration domains |
| No apply stage | No visible recalibration commit |

---

# Summary

During Detection Sensitivity calibration:

1. App performs repeated short encrypted polling transactions.
2. App transitions into indexed table reads via opcode `0f77`.
3. Device returns structured numeric tables.
4. No modification or write-back stage is observed.
5. No streaming or recalculation command is visible in this capture.

This flow currently appears to be a **structured calibration table extraction process preceded by status polling**, with no observable AI-driven recalibration stage in this trace.
