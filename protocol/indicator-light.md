# Opcode Documentation – Indicator Light

---

# 1. Command Identifier

| Bytes | Meaning |
|------:|---------|
| 0f76  | Device command group / identifier |
| 06    | Indicator Light opcode |

| Combined | Value |
|---------:|-------|
| Group + Opcode | 0f7606 |

---

# 2. Plaintext Payload Structure

| Offset | Length | Field | Example | Description |
|------:|-------:|-------|---------|-------------|
| 0 | 2 bytes | Group | 0f76 | Device command group |
| 2 | 1 byte  | Opcode | 06 | Indicator Light |
| 3 | 1 byte  | State | 00 or 01 | Boolean value |

---

# 3. Parameter Specification

| State Value | Meaning |
|------------:|---------|
| 00 | Indicator OFF |
| 01 | Indicator ON |

| Encoding | Type |
|----------|------|
| uint8 | Boolean (0 = false, 1 = true) |

---

# 4. Observed Payloads

| Full Plaintext | Meaning |
|---------------|---------|
| 0f760600 | Disable indicator light |
| 0f760601 | Enable indicator light |

---

# 5. Encryption & Transmission

| Step | Action |
|-----:|--------|
| 1 | Obtain IV from device (see `protocol-spec.md`) |
| 2 | Encrypt full plaintext payload (e.g. `0f760601`) using AES-CTR |
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
