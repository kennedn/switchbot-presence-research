#!/usr/bin/env python3
import argparse
import asyncio
import binascii
import logging
import random
import time
from typing import Optional, Dict, Any

from bleak import BleakScanner
from bleak.exc import BleakError

SWITCHBOT_COMPANY_ID = 0x0969


def _hex(b: bytes) -> str:
    return binascii.hexlify(b).decode("ascii")


def parse_switchbot_presence(mfr_payload: bytes) -> Optional[Dict[str, Any]]:
    if len(mfr_payload) < 12:
        return None

    seq = mfr_payload[6]
    flags = mfr_payload[7]

    adaptive = bool(flags & 0x80)
    motion = bool(flags & 0x40)
    battery_range = (flags >> 2) & 0x03

    duration = (mfr_payload[8] << 8) | mfr_payload[9]
    trigger = mfr_payload[10]

    led = bool(mfr_payload[11] & 0x80)
    light_level = mfr_payload[11] & 0x1F

    return {
        "seq": seq,
        "adaptive": adaptive,
        "motion": motion,
        "battery_range_bucket": battery_range,
        "duration": duration,
        "trigger": trigger,
        "led": led,
        "light_level_0_31": light_level,
    }


def _configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(message)s",
    )


def _make_scanner(
    detection_callback,
    iface: Optional[str],
    *,
    active_scan: bool,
    rssi_floor: int,
    duplicate_data: bool,
) -> BleakScanner:
    # Notes:
    # - BlueZ-specific options live under `bluez={...}`.
    # - Recreating the scanner after failures is important; a stale scanner may never recover.
    scanner_kwargs: Dict[str, Any] = {}
    if iface:
        scanner_kwargs["adapter"] = iface

    bluez_opts = {
        "filters": {
            # DuplicateData keeps repeated adverts flowing (useful for presence sensors).
            "DuplicateData": bool(duplicate_data),
            "RSSI": int(rssi_floor),
        }
    }

    if active_scan:
        return BleakScanner(
            detection_callback,
            scanning_mode="active",
            bluez=bluez_opts,
            **scanner_kwargs,
        )
    else:
        return BleakScanner(
            detection_callback,
            bluez=bluez_opts,
            **scanner_kwargs,
        )


async def _run_scanner_once(
    *,
    iface: Optional[str],
    only_switchbot: bool,
    active_scan: bool,
    rssi_floor: int,
    duplicate_data: bool,
    watchdog_secs: float,
    run_state: Dict[str, Any],
) -> None:
    """
    Runs a scanner until:
      - an exception occurs (propagates), or
      - watchdog triggers (raises RuntimeError), or
      - task is cancelled.
    Updates run_state["seen_valid"] to True once a valid SwitchBot frame is seen.
    """
    log = logging.getLogger("ble-scan")

    last_seen_monotonic = time.monotonic()
    run_state["seen_valid"] = False  # reset per run

    def detection_callback(device, advertisement_data):
        nonlocal last_seen_monotonic
        last_seen_monotonic = time.monotonic()

        addr = device.address
        rssi = getattr(device, "rssi", None)

        mfr = getattr(advertisement_data, "manufacturer_data", None)
        if not mfr:
            return

        for company_id, payload in mfr.items():
            # If you want to filter strictly:
            if only_switchbot and company_id != SWITCHBOT_COMPANY_ID:
                continue

            payload_hex = _hex(payload)

            parsed = (
                parse_switchbot_presence(payload)
                if company_id == SWITCHBOT_COMPANY_ID
                else None
            )

            # This is the "valid message received" condition:
            if parsed is not None:
                run_state["seen_valid"] = True

            base = (
                f"{addr} rssi={rssi} "
                f"company=0x{company_id:04x} "
                f"mfrlen={len(payload)} "
                f"mfr={payload_hex}"
            )

            if parsed:
                base += (
                    f" | motion={int(parsed['motion'])}"
                    f" adaptive={int(parsed['adaptive'])}"
                    f" duration={parsed['duration']}"
                    f" trig={parsed['trigger']}"
                    f" batt_bucket={parsed['battery_range_bucket']}"
                    f" light={parsed['light_level_0_31']}"
                    f" led={int(parsed['led'])}"
                    f" seq={parsed['seq']}"
                )
            elif company_id == SWITCHBOT_COMPANY_ID:
                base += " | switchbot (unparsed)"

            log.info(base)

    scanner = _make_scanner(
        detection_callback,
        iface,
        active_scan=active_scan,
        rssi_floor=rssi_floor,
        duplicate_data=duplicate_data,
    )

    log.info(
        "Starting BLE scan (iface=%s active=%s rssi_floor=%s dup=%s watchdog=%ss)",
        iface,
        active_scan,
        rssi_floor,
        duplicate_data,
        watchdog_secs,
    )

    await scanner.start()
    try:
        # Main loop: keep process alive; optionally watchdog for “silent stall”.
        while True:
            await asyncio.sleep(1)

            if watchdog_secs > 0:
                idle = time.monotonic() - last_seen_monotonic
                if idle >= watchdog_secs:
                    raise RuntimeError(
                        f"Watchdog: no advertisements seen for {idle:.1f}s (>= {watchdog_secs}s)."
                    )
    finally:
        # If BlueZ is mid-reset this can also throw; we let the caller handle it.
        log.info("Stopping BLE scan")
        await scanner.stop()


async def scan_forever(args) -> None:
    log = logging.getLogger("ble-scan")

    # Exponential backoff for restart loop
    attempt = 0
    delay = args.restart_delay

    while True:
        # State object persists long enough for scan_forever() to examine it on failure
        run_state: Dict[str, Any] = {"seen_valid": False}

        try:
            await _run_scanner_once(
                iface=args.iface,
                only_switchbot=args.only_switchbot,
                active_scan=args.active_scan,
                rssi_floor=args.rssi_floor,
                duplicate_data=args.duplicate_data,
                watchdog_secs=args.watchdog,
                run_state=run_state,
            )

        except asyncio.CancelledError:
            raise

        except (BleakError, OSError, RuntimeError) as e:
            # If we had at least one valid message during this run, reset backoff
            # so the next failure sequence starts from the minimum delay again.
            if run_state.get("seen_valid"):
                attempt = 0
                delay = args.restart_delay
                log.info(
                    "Valid message received during last run; resetting backoff (delay=%.2fs).",
                    delay,
                )

            attempt += 1
            # Jitter prevents lockstep if multiple processes restart together.
            jitter = random.uniform(0, min(1.0, delay * 0.1))
            sleep_for = min(args.backoff_max, delay) + jitter

            log.warning(
                "Scanner failed (attempt %d): %s. Restarting in %.2fs",
                attempt,
                repr(e),
                sleep_for,
            )

            await asyncio.sleep(sleep_for)
            delay = min(args.backoff_max, delay * args.backoff_factor)

            # Continue loop, which recreates the scanner (important for recovery).
            continue

        except Exception as e:
            # Unknown errors: still restart, but log loudly.
            if run_state.get("seen_valid"):
                attempt = 0
                delay = args.restart_delay
                log.info(
                    "Valid message received during last run; resetting backoff (delay=%.2fs).",
                    delay,
                )

            attempt += 1
            jitter = random.uniform(0, min(1.0, delay * 0.1))
            sleep_for = min(args.backoff_max, delay) + jitter
            log.exception(
                "Unexpected error (attempt %d): %r. Restarting in %.2fs",
                attempt,
                e,
                sleep_for,
            )
            await asyncio.sleep(sleep_for)
            delay = min(args.backoff_max, delay * args.backoff_factor)
            continue


def build_arg_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", default=None, help="BlueZ adapter (e.g. hci0).")
    ap.add_argument(
        "--only-switchbot",
        action="store_true",
        help="Only log SwitchBot company ID frames.",
    )
    ap.add_argument("--active-scan", action="store_true", help="Use active scanning mode.")
    ap.add_argument("--rssi-floor", type=int, default=-100, help="RSSI filter floor (BlueZ filter).")

    # Note: With store_true, default False is typical. Keeping your original behavior
    # (default True) would be better expressed as store_false on a "--no-duplicate-data" flag.
    ap.add_argument(
        "--duplicate-data",
        action="store_true",
        default=True,
        help="Request duplicate advertisements (BlueZ DuplicateData filter).",
    )

    ap.add_argument(
        "--watchdog",
        type=float,
        default=30.0,
        help="Restart if no advertisements seen for N seconds (0 disables).",
    )

    ap.add_argument("--log-level", default="INFO", help="DEBUG, INFO, WARNING, ERROR")

    ap.add_argument(
        "--restart-delay",
        type=float,
        default=1.0,
        help="Initial restart delay in seconds after failure.",
    )
    ap.add_argument(
        "--backoff-factor",
        type=float,
        default=2.0,
        help="Backoff multiplier after each failure.",
    )
    ap.add_argument(
        "--backoff-max",
        type=float,
        default=30.0,
        help="Maximum restart delay in seconds.",
    )

    return ap


async def main():
    ap = build_arg_parser()
    args = ap.parse_args()
    _configure_logging(args.log_level)

    logging.getLogger("ble-scan").info("Scanning BLE advertisements… Ctrl+C to stop")
    await scan_forever(args)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
