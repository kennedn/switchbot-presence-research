# SwitchBot BLE Protocol Research

This repo contains notes and tooling used to capture and document portions of the SwitchBot Android app’s BLE protocol for the mmwave presence sensor

## Repository Layout

- `protocol/`
  - Markdown protocol documentation (message framing, IV acquisition, encrypted payload structure, opcode behaviors, etc.).
  - These docs are derived from live captures and are intended to be updated as new flows are observed.

- `frida/`
  - Frida scripts used to instrument the Android app and log:
    - GATT reads/writes
    - JCA crypto usage (AES key/IV, mode, inputs/outputs)
    - Encrypted/plaintext payload correlation

- `get_iv.py`
  - Small primitive to exercise and validate the “get IV” behavior outside of the app.
  - Useful for confirming request/response framing and the IV-return pattern.

- `sniff_switchbot.py`
  - BLE sniffing / capture helper script.
  - Used to observe characteristic traffic and validate what is actually sent over the air.

## Requirements

- uv
- `frida` + `frida-tools`
- Android device with USB debugging enabled
- Bluetooth adapter

## Capturing With Frida

Current invocation:

```bash
frida -U -f com.theswitchbot.switchbot \
  -l encrypt_and_gatt_v3.js \
  -l jca_aes_key_iv_probe.js
