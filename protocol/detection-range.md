# Opcode Documentation – Detection Range

---

# 1. Command Identifier

| Bytes | Meaning |
|------:|---------|
| 0f76  | Device command group / identifier |
| 04    | Detection Range opcode |

| Combined | Value |
|---------:|-------|
| Group + Opcode | 0f7604 |

---

# 2. Plaintext Payload Structure

| Offset | Length | Field | Example | Description |
|------:|-------:|-------|---------|-------------|
| 0 | 2 bytes | Group | 0f76 | Device command group |
| 2 | 1 byte  | Opcode | 04 | Detection Range |
| 3 | 1 byte  | Parameter ID | 01 | Range selector / field identifier |
| 4 | 2 bytes | Range | 00fa | Range value (big-endian uint16, millimeters) |

| Range Conversion | Formula |
|-----------------:|---------|
| Millimeters → meters | meters = uint16_mm / 1000 |

---

# 3. Parameter Specification

| Parameter | Type | Encoding | Unit | Meaning |
|----------|------|----------|------|---------|
| Parameter ID | uint8 | Hex literal | N/A | Field identifier (observed constant `01`) |
| Range | uint16 | Big-endian | millimeters | Detection range |

---

# 4. App Range and Observed Values

| Source | Minimum | Maximum |
|--------|--------:|--------:|
| App UI range | 0.25 m | 8.00 m |

| Meters | Millimeters | Encoded (uint16 BE) | Payload Suffix (ParamID + Range) |
|-------:|------------:|---------------------|----------------------------------|
| 0.25 | 250  | 00fa | 0100fa |
| 3.00 | 3000 | 0bb8 | 010bb8 |
| 8.00 | 8000 | 1f40 | 011f40 |

| Full Example Payload | Meaning |
|----------------------|---------|
| 0f76040100fa | Set detection range to 0.25 m |
| 0f7604011f40 | Set detection range to 8.00 m |

---

# 5. Encryption & Transmission

| Step | Action |
|-----:|--------|
| 1 | Obtain IV from device (see `protocol-spec.md`) |
| 2 | Encrypt full plaintext payload (e.g. `0f76040100fa`) using AES-CTR |
| 3 | Wrap ciphertext using BLE wrapper format |

| BLE Wrapper Format | Value |
|--------------------|-------|
| Header | 57 |
| KeyID | (account-specific) |
| IV Prefix | first 2 bytes of IV |
| Ciphertext | AES-CTR(plaintext) |

---

# 6. Device Response

| Response Type | Format | Meaning |
|--------------|--------|---------|
| ACK | 01 [KeyID] [IV Prefix] | Success, echoed KeyID and IV prefix |
