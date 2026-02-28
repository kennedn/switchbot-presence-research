# Opcode Documentation – Unoccupied Timer

---

# 1. Command Identifier

| Bytes | Meaning |
|--------|------------|
| 0f76 | Device command group / identifier |
| 05 | Unoccupied Timer opcode |

Combined:

```

0f7605

```

---

# 2. Plaintext Payload Structure

Full plaintext format:

```

0f7605000f

```

| Offset | Length | Field | Example | Description |
|--------|--------|--------|--------|------------|
| 0 | 2 bytes | Group | 0f76 | Device command group |
| 2 | 1 byte | Opcode | 05 | Unoccupied Timer |
| 3 | 2 bytes | Seconds | 000f | Timeout value (big-endian) |

---

# 3. Parameter Specification

| Parameter | Type | Encoding | Observed Range | Meaning |
|------------|------|----------|----------------|---------|
| Seconds | uint16 | Big-endian | 0005 – 00b3 | Seconds without motion before unoccupied state |

