# Detection Sensitivity – Calibration & Polling Flow

## Overview

This flow is triggered when entering the **Detection Sensitivity calibration dialog**.

Observed behavior consists of:

1. Repeated IV acquisition
2. Periodic encrypted polling using opcode `0f7701`
3. Structured indexed table reads using opcode family `0f77`
4. No observed commit/write operations

The flow is structured and read-dominant.

---

# Phase 1 – Readiness Polling Phase

Before structured table iteration begins, the app performs repeated encrypted polling transactions.

This phase uses opcode family `0f77`.

---

## 1.1 IV Acquisition (Before Each Transaction)

Each encrypted transaction is preceded by an IV fetch.

### App → Device (Unencrypted)

| Offset | Bytes  | Description            |
| ------ | ------ | ---------------------- |
| 0      | 57     | Protocol header        |
| 1      | 00     | KeyID slot (empty)     |
| 2–3    | 0000   | IV prefix slot (empty) |
| 4–6    | 0f2103 | Unencrypted opcode     |
| 7      | b9     | KeyID                  |

Example:

```
570000000f2103b9
```

---

### Device → App

| Offset | Bytes    | Description             |
| ------ | -------- | ----------------------- |
| 0      | 01       | Status (01 = success)   |
| 1      | 00       | KeyID slot (unused)     |
| 2–3    | 0000     | IV prefix slot (unused) |
| 4–19   | 16 bytes | Full IV for AES-CTR     |

Example:

```
010000001ed1f6f6cf519226b1ecdd9b7441f534
```

This IV is used immediately for a single AES-CTR encrypted transaction.

Each encrypted exchange repeats this IV acquisition step.

---

## 1.2 Encrypted Poll Command (`0f7701`)

After IV acquisition, the app sends the encrypted command:

```
0f7701
```

Structure:

| Offset | Bytes | Description             |
| ------ | ----- | ----------------------- |
| 0–1    | 0f77  | Opcode family           |
| 2      | 01    | Poll / readiness opcode |

This is the only request observed during this phase.

The app sends this request every few seconds until a successful status response is returned.

---

## 1.3 Decrypted Poll Responses

Observed decrypted responses:

| Plaintext | Interpretation |
| --------- | -------------- |
| 0002      | Failure state  |
| 0103      | Success state  |

Response structure:

| Offset | Bytes       | Description                    |
| ------ | ----------- | ------------------------------ |
| 0      | Status byte | 00 = failure, 01 = success     |
| 1      | Unknown     | Possibly phase/state indicator |

Interpretation:

* `0002`

  * `00` = failure
  * `02` = unknown state/phase

* `0103`

  * `01` = success
  * `03` = unknown state/phase

Observed behavior:

* App repeatedly sends `0f7701`
* Device returns `0002`
* Polling continues
* Once device returns `0103`
* App transitions to next phase

This phase appears to gate progression into structured table extraction.

---

# Phase 2 – Structured Table Read Phase

Once the poll returns `0103`, the app transitions into indexed reads.

Observed range:

```
0f77030100
...
0f7703030d
```

---

## 2.1 Encrypted Request Structure

After IV acquisition:

| Offset | Bytes      | Description               |
| ------ | ---------- | ------------------------- |
| 0      | 57         | Header                    |
| 1      | b9         | KeyID                     |
| 2–3    | IV[0–1]    | First two bytes of IV     |
| 4–N    | Ciphertext | AES-CTR encrypted payload |

---

## 2.2 Plaintext Request Pattern

Decrypted payload structure:

| Offset | Bytes       | Description       |
| ------ | ----------- | ----------------- |
| 0–1    | 0f77        | Opcode family     |
| 2      | 03          | Table read opcode |
| 3      | Subtable ID | Observed: 01, 03  |
| 4      | Row index   | 00–0d observed    |

Example requests:

| Plaintext  | Meaning                            |
| ---------- | ---------------------------------- |
| 0f77030100 | Read group 03, subtable 01, row 00 |
| 0f7703010d | Read group 03, subtable 01, row 13 |
| 0f77030300 | Read group 03, subtable 03, row 00 |
| 0f7703030d | Read group 03, subtable 03, row 13 |

Observed behavior:

* Row index increments sequentially
* Subtable 01 is read fully
* Subtable 03 is then read fully
* No writes observed between reads

---

## 2.3 Plaintext Response Structure

Decrypted response format:

| Offset | Bytes     | Description |
| ------ | --------- | ----------- |
| 0      | Row index | Echo/index  |
| 1–2    | Value 1   | uint16 (LE) |
| 3–4    | Value 2   | uint16 (LE) |
| 5–6    | Value 3   | uint16 (LE) |
| 7–8    | Value 4   | uint16 (LE) |
| 9–10   | Value 5   | uint16 (LE) |
| 11–12  | Value 6   | uint16 (LE) |
| 13–14  | Value 7   | uint16 (LE) |

Example decrypted response:

```
00017b0197018801bf01c0016c0170
```

Decoded:

| Field | Hex  | Decimal |
| ----- | ---- | ------- |
| Row   | 00   | 0       |
| V1    | 017b | 379     |
| V2    | 0197 | 407     |
| V3    | 0188 | 392     |
| V4    | 01bf | 447     |
| V5    | 01c0 | 448     |
| V6    | 016c | 364     |
| V7    | 0170 | 368     |

Row format:

* 1 byte row index
* 7 × uint16 values
* Fixed-width structure

---

# Phase 3 – Observed Structural Characteristics

| Characteristic        | Observation                                   |
| --------------------- | --------------------------------------------- |
| Read-only behavior    | No write/commit opcodes observed              |
| Explicit phase gate   | Polling must return `0103` before reads begin |
| Indexed iteration     | Row index increments sequentially             |
| Multiple subtables    | Subtable 01 and 03 observed                   |
| Fixed-width rows      | 1 byte index + 7 × uint16 values              |
| Per-transaction IV    | Every exchange preceded by IV acquisition     |
| Deterministic polling | `0f7701` repeated until success               |

---

# Behavioral Interpretation

| Phase              | Likely Purpose                            |
| ------------------ | ----------------------------------------- |
| `0f7701` polling   | Device readiness / calibration state gate |
| `0f7703xx` reads   | Calibration LUT extraction                |
| Subtable variation | Multiple calibration domains              |
| No apply stage     | No visible recalibration commit           |

Notably:

* `34c5` and `35c4` are not requested by the app.
* These were encrypted payload artifacts, not actual plaintext commands.
* The only observed command in Phase 1 is `0f7701`.

---

# Summary

During Detection Sensitivity calibration:

1. App repeatedly fetches IV and sends encrypted `0f7701`.
2. Device returns `0002` (failure) until ready.
3. When device returns `0103` (success), app transitions phases.
4. App performs indexed table reads using `0f7703`.
5. Device returns structured fixed-width numeric rows.
6. No write, commit, or recalibration apply command is observed.
7. No streaming or recalculation opcode appears in this capture.

This flow appears to be a **gated calibration table extraction process**, where readiness is polled via `0f7701`, followed by structured LUT retrieval once the device signals success.

