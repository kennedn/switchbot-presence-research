import asyncio
from bleak import BleakClient

MAC = "B0:E9:FE:99:6A:D7"

TX_UUID = "cba20002-224d-11e6-9fb8-0002a5d5c51b"  # write
RX_UUID = "cba20003-224d-11e6-9fb8-0002a5d5c51b"  # notify

TRIGGER_HEX = "570000000f2103b9"  # IV-trigger packet from your logs


def to_hex(b: bytes) -> str:
    return b.hex()


def parse_iv(data: bytes) -> bytes | None:
    # Based on your sample RX 20 bytes, common pattern is "header + 16-byte IV"
    # This assumes last 16 bytes are the IV.
    if len(data) >= 16:
        return data[-16:]
    return None


async def connect_with_retry(mac: str, attempts: int = 5) -> BleakClient:
    last_err: Exception | None = None

    for i in range(1, attempts + 1):
        print(f"[BLE] connect attempt {i}/{attempts}")
        client = BleakClient(mac, timeout=20.0)

        try:
            await client.connect()
            if client.is_connected:
                print("[BLE] connected")
                return client

            raise RuntimeError("connect() returned but client not connected")

        except Exception as e:
            last_err = e
            msg = str(e)
            print(f"[BLE] connect failed: {e}")

            # Only disconnect if we actually connected. Disconnecting a half-open attempt
            # can contribute to org.bluez.Error.InProgress.
            if getattr(client, "is_connected", False):
                try:
                    await client.disconnect()
                except Exception:
                    pass

            # Give BlueZ time to unwind any pending operation
            if "org.bluez.Error.InProgress" in msg:
                await asyncio.sleep(4.0)
            else:
                await asyncio.sleep(2.0)

    raise RuntimeError(f"Failed to connect after retries: {last_err}")


async def main():
    client = await connect_with_retry(MAC, attempts=5)

    iv_future: asyncio.Future[bytes] = asyncio.get_running_loop().create_future()

    def on_notify(_: int, data: bytearray):
        b = bytes(data)
        print(f"[RX] len={len(b)} hex={to_hex(b)}")

        iv = parse_iv(b)
        if iv is not None:
            print(f"[IV] len={len(iv)} hex={to_hex(iv)}")
            if not iv_future.done():
                iv_future.set_result(iv)

    try:
        # Enable notifications before sending trigger
        await client.start_notify(RX_UUID, on_notify)
        print("[BLE] notify enabled")

        # Small settle delay (helps BlueZ reliability)
        await asyncio.sleep(0.2)

        trigger = bytes.fromhex(TRIGGER_HEX)
        print(f"[TX] len={len(trigger)} hex={to_hex(trigger)}")

        # If your characteristic REQUIRES write-with-response, keep response=True.
        # If it works without response, response=False reduces GATT round-trips.
        await client.write_gatt_char(TX_UUID, trigger, response=True)

        try:
            await asyncio.wait_for(iv_future, timeout=5.0)
            print("[DONE] IV captured")
        except asyncio.TimeoutError:
            print("[WARN] Timed out waiting for IV")

        await asyncio.sleep(0.2)

    finally:
        try:
            await client.stop_notify(RX_UUID)
        except Exception:
            pass
        try:
            await client.disconnect()
        except Exception:
            pass
        print("[BLE] disconnected")


if __name__ == "__main__":
    asyncio.run(main())
