/**
 * gatt_nordic_plus_dem_full_state_dump.js
 *
 * Keeps:
 *  - Android BluetoothGatt TX + notification/CCCD config
 *  - WoBleClient TX/RX (Nordic BleManager callback path)
 *  - Nordic chunking visibility (WriteRequest.U / m70935U)
 *
 * Adds:
 *  - DEM full static field dump singleton (no guessing field names)
 *  - Calls dump BEFORE/AFTER DEM.e(...) and DEM.p(...)
 *
 * No DEM crypto internals hooks.
 */

Java.perform(function () {
  // -----------------------
  // Common helpers
  // -----------------------
  const Exception = Java.use('java.lang.Exception');

  function bytesToHex(barr, maxBytes) {
    if (!barr) return "null";
    let a;
    try { a = Java.array('byte', barr); } catch (_) { return "<?>"; }
    const limit = (maxBytes && maxBytes > 0) ? Math.min(a.length, maxBytes) : a.length;
    let s = "";
    for (let i = 0; i < limit; i++) {
      let v = a[i]; if (v < 0) v += 256;
      s += ("0" + v.toString(16)).slice(-2);
    }
    if (limit < a.length) s += `...(+${a.length - limit}b)`;
    return s;
  }

  function bytesLen(barr) {
    try { return Java.array('byte', barr).length; } catch (_) { return -1; }
  }

  function shortUuid(uuidStr) {
    if (!uuidStr) return "null";
    return uuidStr.toLowerCase();
  }

  function getMacFromGatt(gatt) {
    try {
      const dev = gatt.getDevice();
      if (dev) return dev.getAddress().toString();
    } catch (_) {}
    return "unknown";
  }

  function getUuidFromCh(ch) {
    try { return shortUuid(ch.getUuid().toString()); } catch (_) {}
    return "unknown";
  }

  function getUuidFromDesc(desc) {
    try { return shortUuid(desc.getUuid().toString()); } catch (_) {}
    return "unknown";
  }

  function getChFromDesc(desc) {
    try { return desc.getCharacteristic(); } catch (_) { return null; }
  }

  function getHexFromChValue(ch, maxBytes) {
    try { return bytesToHex(ch.getValue(), maxBytes) || "null"; } catch (_) {}
    return "unknown";
  }

  function getHexFromDescValue(desc, maxBytes) {
    try { return bytesToHex(desc.getValue(), maxBytes) || "null"; } catch (_) {}
    return "unknown";
  }

  function logGattTx(mac, uuid, hex, extra) {
    const len = (hex && hex !== "null" && hex !== "unknown")
      ? Math.floor(hex.replace(/\.\.\.\(\+\d+b\)$/, "").length / 2)
      : "n/a";
    console.log(`\n[GATT TX WRITE] mac=${mac} uuid=${uuid} len=${len}${extra ? " " + extra : ""}`);
    console.log(`  data=${hex}`);
  }

  function logGattCfg(tag, mac, msg) {
    console.log(`\n[GATT CFG] mac=${mac} ${tag} ${msg}`);
  }

  function logRx(tag, mac, uuid, barr, extra) {
    const len = bytesLen(barr);
    const hex = bytesToHex(barr, 64);
    console.log(`\n[${tag}] mac=${mac} uuid=${uuid} len=${len}${extra ? " " + extra : ""}`);
    console.log(`  data=${hex}`);
  }

  function safeClassName(obj) {
    try { return obj ? obj.getClass().getName() : "null"; } catch (_) { return "<?>"; }
  }


  // -----------------------
  // 1) GATT TX + CFG
  // -----------------------
  try {
    const BluetoothGatt = Java.use('android.bluetooth.BluetoothGatt');

    // writeCharacteristic(BluetoothGattCharacteristic)
    try {
      const ov1 = BluetoothGatt.writeCharacteristic.overload('android.bluetooth.BluetoothGattCharacteristic');
      ov1.implementation = function (ch) {
        const mac = getMacFromGatt(this);
        const uuid = getUuidFromCh(ch);
        const hex = getHexFromChValue(ch, 96);
        logGattTx(mac, uuid, hex);
        return ov1.call(this, ch);
      };
      console.log('[+] Hooked BluetoothGatt.writeCharacteristic(BluetoothGattCharacteristic)');
    } catch (e) {
      console.log('[-] No overload: BluetoothGatt.writeCharacteristic(BluetoothGattCharacteristic): ' + e);
    }

    // readCharacteristic(BluetoothGattCharacteristic)
    try {
      const ro = BluetoothGatt.readCharacteristic.overload('android.bluetooth.BluetoothGattCharacteristic');
      ro.implementation = function (ch) {
        const mac = getMacFromGatt(this);
        const uuid = getUuidFromCh(ch);
        logGattCfg('READ-REQ', mac, `uuid=${uuid}`);
        return ro.call(this, ch);
      };
      console.log('[+] Hooked BluetoothGatt.readCharacteristic(BluetoothGattCharacteristic)');
    } catch (e) {
      console.log('[-] No overload: BluetoothGatt.readCharacteristic(BluetoothGattCharacteristic): ' + e);
    }

    // setCharacteristicNotification(ch, enable)
    try {
      const sn = BluetoothGatt.setCharacteristicNotification.overload(
        'android.bluetooth.BluetoothGattCharacteristic',
        'boolean'
      );
      sn.implementation = function (ch, enable) {
        const mac = getMacFromGatt(this);
        const uuid = getUuidFromCh(ch);
        logGattCfg('setCharacteristicNotification', mac, `uuid=${uuid} enable=${enable}`);
        return sn.call(this, ch, enable);
      };
      console.log('[+] Hooked BluetoothGatt.setCharacteristicNotification(ch, boolean)');
    } catch (e) {
      console.log('[-] No overload: BluetoothGatt.setCharacteristicNotification(ch, boolean): ' + e);
    }

    // writeDescriptor(desc) for CCCD
    try {
      const wd = BluetoothGatt.writeDescriptor.overload('android.bluetooth.BluetoothGattDescriptor');
      wd.implementation = function (desc) {
        const mac = getMacFromGatt(this);
        const dUuid = getUuidFromDesc(desc);
        const ch = getChFromDesc(desc);
        const chUuid = ch ? getUuidFromCh(ch) : "unknown";
        const hex = getHexFromDescValue(desc, 32);
        const len = bytesLen(desc.getValue());
        console.log(`\n[GATT CFG] mac=${mac} writeDescriptor ch_uuid=${chUuid} desc_uuid=${dUuid} len=${len}`);
        console.log(`  data=${hex}`);
        return wd.call(this, desc);
      };
      console.log('[+] Hooked BluetoothGatt.writeDescriptor(BluetoothGattDescriptor)');
    } catch (e) {
      console.log('[-] No overload: BluetoothGatt.writeDescriptor(BluetoothGattDescriptor): ' + e);
    }

  } catch (e) {
    console.log('[-] Failed hooking BluetoothGatt: ' + e);
  }

  // -----------------------
  // 2) WoBleClient + callback RX path (Nordic)
  // -----------------------
  try {
    const WoBleClient = Java.use('com.theswitchbot.common.ble.impl.WoBleClient');

    // i0([B, int) -> write dispatch (TX)
    try {
      const i0 = WoBleClient.i0.overload('[B', 'int');
      i0.implementation = function (data, writeType) {
        console.log(`\n[WoBleClient TX] i0 writeType=${writeType} len=${bytesLen(data)}`);
        console.log(`  data=${bytesToHex(data, 96)}`);
        return i0.call(this, data, writeType);
      };
      console.log('[+] Hooked WoBleClient.i0([B, int)');
    } catch (e) {
      console.log('[-] Failed hooking WoBleClient.i0: ' + e);
    }

    // p0([B, int, LongAckSupport) -> queue request (TX)
    try {
      const p0 = WoBleClient.p0.overload('[B', 'int', 'com.theswitchbot.common.ble.LongAckSupport');
      p0.implementation = function (data, writeType, longAck) {
        console.log(`\n[WoBleClient TX] p0 writeType=${writeType} len=${bytesLen(data)} longAck=${safeClassName(longAck)}`);
        console.log(`  data=${bytesToHex(data, 96)}`);
        return p0.call(this, data, writeType, longAck);
      };
      console.log('[+] Hooked WoBleClient.p0([B, int, LongAckSupport)');
    } catch (e) {
      console.log('[-] Failed hooking WoBleClient.p0: ' + e);
    }

    // o0([B) -> reply handler (RX)
    try {
      const o0 = WoBleClient.o0.overload('[B');
      o0.implementation = function (reply) {
        console.log(`\n[WoBleClient RX] o0 len=${bytesLen(reply)}`);
        console.log(`  data=${bytesToHex(reply, 96)}`);
        return o0.call(this, reply);
      };
      console.log('[+] Hooked WoBleClient.o0([B)');
    } catch (e) {
      console.log('[-] Failed hooking WoBleClient.o0: ' + e);
    }

    // t0(Function2) -> sets notify callback
    try {
      const t0 = WoBleClient.t0.overload('kotlin.jvm.functions.Function2');
      t0.implementation = function (cb) {
        console.log(`\n[WoBleClient] t0 set mNotificationCallback = ${safeClassName(cb)} | ${cb}`);
        return t0.call(this, cb);
      };
      console.log('[+] Hooked WoBleClient.t0(Function2)');
    } catch (e) {
      console.log('[-] Failed hooking WoBleClient.t0: ' + e);
    }

  } catch (e) {
    console.log('[-] WoBleClient not available: ' + e);
  }

  // WoBleGattCallback.U6 + t7/u7 (RX)
  try {
    const WGC = Java.use('com.theswitchbot.common.ble.impl.WoBleClient$WoBleGattCallback');

    try {
      const U6 = WGC.U6.overload('android.bluetooth.BluetoothGatt', 'android.bluetooth.BluetoothGattCharacteristic');
      U6.implementation = function (gatt, ch) {
        const mac = getMacFromGatt(gatt);
        const uuid = getUuidFromCh(ch);
        const v = ch.getValue();
        logRx('WoBleGattCallback RX', mac, uuid, v);
        return U6.call(this, gatt, ch);
      };
      console.log('[+] Hooked WoBleGattCallback.U6(gatt, ch)');
    } catch (e) {
      console.log('[-] Failed hooking WoBleGattCallback.U6: ' + e);
    }

    ['t7', 'u7'].forEach(function (name) {
      try {
        const m = WGC[name];
        if (!m) return;
        const ov = m.overload(
          'com.theswitchbot.common.ble.impl.WoBleClient',
          'com.theswitchbot.common.ble.impl.WoBleClient$WoBleGattCallback',
          'android.bluetooth.BluetoothDevice',
          'no.nordicsemi.android.ble.data.Data'
        );
        ov.implementation = function (client, cb, dev, dataObj) {
          let mac = "unknown";
          try { mac = dev ? dev.getAddress().toString() : mac; } catch (_) {}
          let barr = null;
          try { barr = dataObj ? dataObj.m70964c() : null; } catch (_) {}
          console.log(`\n[WoBleGattCallback RX] ${name} device=${mac} data.len=${bytesLen(barr)}`);
          console.log(`  data=${bytesToHex(barr, 96)}`);
          return ov.call(this, client, cb, dev, dataObj);
        };
        console.log(`[+] Hooked WoBleGattCallback.${name}(..., Data)`);
      } catch (e) {
        // ok
      }
    });

  } catch (e) {
    console.log('[-] WoBleGattCallback not available: ' + e);
  }

  // WoBleManager.L(mac, [B) notify channel into app
  try {
    const WoBleManager = Java.use('com.theswitchbot.common.ble.impl.WoBleManager');
    try {
      const L = WoBleManager.L.overload('java.lang.String', '[B');
      L.implementation = function (mac, data) {
        console.log(`\n[WoBleManager NOTIFY] L mac=${mac} len=${bytesLen(data)}`);
        console.log(`  data=${bytesToHex(data, 96)}`);
        return L.call(this, mac, data);
      };
      console.log('[+] Hooked WoBleManager.L(String, [B)');
    } catch (e) {
      console.log('[-] Failed hooking WoBleManager.L: ' + e);
    }
  } catch (e) {
    console.log('[-] WoBleManager not available: ' + e);
  }

  // -----------------------
  // 3) Nordic chunking visibility (WriteRequest.U / m70935U)
  // -----------------------
  try {
    const WriteRequest = Java.use('no.nordicsemi.android.ble.WriteRequest');

    try {
      const U = WriteRequest.U.overload('int');
      U.implementation = function (mtu) {
        const out = U.call(this, mtu);
        console.log(`\n[Nordic TX CHUNK] U mtu=${mtu} len=${bytesLen(out)}`);
        console.log(`  data=${bytesToHex(out, 96)}`);
        return out;
      };
      console.log('[+] Hooked WriteRequest.U(int)');
    } catch (e) {
      try {
        const U2 = WriteRequest.m70935U.overload('int');
        U2.implementation = function (mtu) {
          const out = U2.call(this, mtu);
          console.log(`\n[Nordic TX CHUNK] m70935U mtu=${mtu} len=${bytesLen(out)}`);
          console.log(`  data=${bytesToHex(out, 96)}`);
          return out;
        };
        console.log('[+] Hooked WriteRequest.m70935U(int)');
      } catch (e2) {
        console.log('[-] Nordic chunk hook not installed (ok): ' + e2);
      }
    }
  } catch (e) {
    console.log('[-] WriteRequest not available: ' + e);
  }

  console.log('[+] Loaded: GATT TX/CFG + WoBle TX/RX + Nordic chunking + DEM full static state dump on e/p');
});
