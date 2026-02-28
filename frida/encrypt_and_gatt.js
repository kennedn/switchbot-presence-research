Java.perform(function () {
  const Exception = Java.use('java.lang.Exception');

  // -----------------------
  // Common helpers
  // -----------------------
  function stackHere() {
    return Exception.$new().getStackTrace().toString();
  }

  function bytesToHex(barr) {
    if (!barr) return null;
    const a = Java.array('byte', barr);
    let s = "";
    for (let i = 0; i < a.length; i++) {
      let v = a[i]; if (v < 0) v += 256;
      s += ("0" + v.toString(16)).slice(-2);
    }
    return s;
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

  function getHexFromChValue(ch) {
    try {
      const v = ch.getValue(); // byte[]
      return bytesToHex(v) || "null";
    } catch (_) {}
    return "unknown";
  }

  function logGatt(tag, mac, uuid, hex, extra) {
    const len = (hex && hex !== "null" && hex !== "unknown") ? (hex.length / 2) : "n/a";
    console.log(`\n[${tag}] mac=${mac} uuid=${uuid} len=${len}${extra ? " " + extra : ""}`);
    if (hex !== undefined) console.log(`  data=${hex}`);
  }

  // -----------------------
  // DeviceEncryptManager hooks
  // -----------------------
  function argInfo(a) {
    if (a === null || a === undefined)
      return { t: String(a), v: String(a) };

    try {
      if (a.$className === '[B') {
        const len = Java.array('byte', a).length;
        return { t: '[B', v: `len=${len} hex=${bytesToHex(a)}` };
      }
    } catch (_) {}

    try {
      const cls = a.getClass().getName();
      return { t: cls, v: a.toString() };
    } catch (_) {
      return { t: typeof a, v: String(a) };
    }
  }

  function dumpKotlinPairIfPresent(obj) {
    if (!obj) return false;

    try {
      const Pair = Java.use('kotlin.Pair');
      if (!Pair.class.isInstance(obj)) return false;

      const first = obj.getFirst();
      const second = obj.getSecond();

      console.log(`  RET Pair.first: ${first}`);

      if (second && second.$className === '[B') {
        const len = Java.array('byte', second).length;
        console.log(`  RET Pair.second: [B len=${len} hex=${bytesToHex(second)}`);
      } else {
        let cls = 'null';
        try { cls = second ? second.getClass().getName() : 'null'; } catch (_) {}
        console.log(`  RET Pair.second: ${cls} | ${second}`);
      }

      return true;
    } catch (_) {
      return false;
    }
  }

  function hookAll(klassName, methodName) {
    try {
      const K = Java.use(klassName);
      const m = K[methodName];

      if (!m) {
        console.log(`[-] ${klassName}.${methodName} not found`);
        return;
      }

      m.overloads.forEach(function (ov) {
        const sig = `${klassName}.${methodName}(${ov.argumentTypes.map(t => t.className).join(', ')}) -> ${ov.returnType.className}`;
        console.log(`[+] Hooking ${sig}`);

        ov.implementation = function () {
          console.log(`\n==> ${sig}`);

          for (let i = 0; i < arguments.length; i++) {
            const info = argInfo(arguments[i]);
            console.log(`  arg${i}: ${info.t} | ${info.v}`);
          }

          const ret = ov.apply(this, arguments);

          if (dumpKotlinPairIfPresent(ret)) {
            // already printed
          } else if (ret && ret.$className === '[B') {
            const len = Java.array('byte', ret).length;
            console.log(`  RET: [B len=${len} hex=${bytesToHex(ret)}`);
          } else {
            const r = argInfo(ret);
            console.log(`  RET: ${r.t} | ${r.v}`);
          }

          return ret;
        };
      });

    } catch (e) {
      console.log(`[-] Failed hooking ${klassName}.${methodName}: ${e}`);
    }
  }

  hookAll(
    'com.theswitchbot.devicemodel.compatibility.communication.DeviceEncryptManager',
    'e'
  );
  hookAll(
    'com.theswitchbot.devicemodel.compatibility.communication.DeviceEncryptManager',
    'p'
  );

  // -----------------------
  // GATT TX + subscription plumbing hooks
  // -----------------------
  try {
    const BluetoothGatt = Java.use('android.bluetooth.BluetoothGatt');

    // TX write
    try {
      const ov1 = BluetoothGatt.writeCharacteristic.overload('android.bluetooth.BluetoothGattCharacteristic');
      ov1.implementation = function (ch) {
        const mac = getMacFromGatt(this);
        const uuid = getUuidFromCh(ch);
        const hex = getHexFromChValue(ch);
        logGatt('GATT TX WRITE', mac, uuid, hex);
        return ov1.call(this, ch);
      };
      console.log('[+] Hooked BluetoothGatt.writeCharacteristic(BluetoothGattCharacteristic)');
    } catch (e) {
      console.log('[-] No overload: BluetoothGatt.writeCharacteristic(BluetoothGattCharacteristic): ' + e);
    }

    // TX read request (may not be used)
    try {
      const ovR = BluetoothGatt.readCharacteristic.overload('android.bluetooth.BluetoothGattCharacteristic');
      ovR.implementation = function (ch) {
        const mac = getMacFromGatt(this);
        const uuid = getUuidFromCh(ch);
        logGatt('GATT TX READ-REQ', mac, uuid, undefined);
        return ovR.call(this, ch);
      };
      console.log('[+] Hooked BluetoothGatt.readCharacteristic(BluetoothGattCharacteristic)');
    } catch (e) {
      console.log('[-] No overload: BluetoothGatt.readCharacteristic(BluetoothGattCharacteristic): ' + e);
    }

    // Notification enable/disable
    try {
      const ovN = BluetoothGatt.setCharacteristicNotification.overload(
        'android.bluetooth.BluetoothGattCharacteristic',
        'boolean'
      );
      ovN.implementation = function (ch, enable) {
        const mac = getMacFromGatt(this);
        const uuid = getUuidFromCh(ch);
        console.log(`\n[GATT CFG] mac=${mac} setCharacteristicNotification uuid=${uuid} enable=${enable}`);
        return ovN.call(this, ch, enable);
      };
      console.log('[+] Hooked BluetoothGatt.setCharacteristicNotification(ch, boolean)');
    } catch (e) {
      console.log('[-] No overload: BluetoothGatt.setCharacteristicNotification: ' + e);
    }

    // Descriptor writes (CCCD)
    try {
      const ovWD = BluetoothGatt.writeDescriptor.overload('android.bluetooth.BluetoothGattDescriptor');
      ovWD.implementation = function (desc) {
        let mac = "unknown";
        let duuid = "unknown";
        let cuuid = "unknown";
        let hex = "unknown";

        try { mac = getMacFromGatt(this); } catch (_) {}

        try { duuid = shortUuid(desc.getUuid().toString()); } catch (_) {}

        try {
          const ch = desc.getCharacteristic();
          if (ch) cuuid = shortUuid(ch.getUuid().toString());
        } catch (_) {}

        try { hex = bytesToHex(desc.getValue()) || "null"; } catch (_) {}

        console.log(`\n[GATT CFG] mac=${mac} writeDescriptor ch_uuid=${cuuid} desc_uuid=${duuid} len=${hex === "null" ? "n/a" : (hex.length/2)}`);
        console.log(`  data=${hex}`);
        return ovWD.call(this, desc);
      };
      console.log('[+] Hooked BluetoothGatt.writeDescriptor(BluetoothGattDescriptor)');
    } catch (e) {
      console.log('[-] No overload: BluetoothGatt.writeDescriptor(BluetoothGattDescriptor): ' + e);
    }

  } catch (e) {
    console.log('[-] Failed hooking BluetoothGatt methods: ' + e);
  }

  // -----------------------
  // RX: hook the *actual* BluetoothGattCallback instance used (via connectGatt)
  // -----------------------
  const hookedCbClasses = new Set();

  function hookCallbackClass(className) {
    if (hookedCbClasses.has(className)) return;

    let K = null;
    try { K = Java.use(className); } catch (e) { return; }
    if (!K) return;

    let did = false;

    // Notifications/Indications (this is your RX)
    try {
      if (K.onCharacteristicChanged) {
        const occ = K.onCharacteristicChanged.overload(
          'android.bluetooth.BluetoothGatt',
          'android.bluetooth.BluetoothGattCharacteristic'
        );
        occ.implementation = function (gatt, ch) {
          const mac = getMacFromGatt(gatt);
          const uuid = getUuidFromCh(ch);
          const hex = getHexFromChValue(ch);
          logGatt(`GATT RX NOTIFY @${className}`, mac, uuid, hex);
          return occ.call(this, gatt, ch);
        };
        did = true;
      }
    } catch (_) {}

    // Write complete (status/ACK)
    try {
      if (K.onCharacteristicWrite) {
        const ocw = K.onCharacteristicWrite.overload(
          'android.bluetooth.BluetoothGatt',
          'android.bluetooth.BluetoothGattCharacteristic',
          'int'
        );
        ocw.implementation = function (gatt, ch, status) {
          const mac = getMacFromGatt(gatt);
          const uuid = getUuidFromCh(ch);
          const hex = getHexFromChValue(ch);
          logGatt(`GATT EVT WRITE-CB @${className}`, mac, uuid, hex, `status=${status}`);
          return ocw.call(this, gatt, ch, status);
        };
        did = true;
      }
    } catch (_) {}

    // CCCD write ACK (subscription completed)
    try {
      if (K.onDescriptorWrite) {
        const odw = K.onDescriptorWrite.overload(
          'android.bluetooth.BluetoothGatt',
          'android.bluetooth.BluetoothGattDescriptor',
          'int'
        );
        odw.implementation = function (gatt, desc, status) {
          const mac = getMacFromGatt(gatt);
          let duuid = "unknown";
          let cuuid = "unknown";
          let hex = "unknown";

          try { duuid = shortUuid(desc.getUuid().toString()); } catch (_) {}
          try {
            const ch = desc.getCharacteristic();
            if (ch) cuuid = shortUuid(ch.getUuid().toString());
          } catch (_) {}
          try { hex = bytesToHex(desc.getValue()) || "null"; } catch (_) {}

          console.log(`\n[GATT EVT DESC-WRITE-CB @${className}] mac=${mac} ch_uuid=${cuuid} desc_uuid=${duuid} status=${status}`);
          console.log(`  data=${hex}`);
          return odw.call(this, gatt, desc, status);
        };
        did = true;
      }
    } catch (_) {}

    if (did) {
      hookedCbClasses.add(className);
      console.log(`[+] Hooked actual callback class: ${className}`);
    }
  }

  // Hook BluetoothDevice.connectGatt(...) to learn the real callback class name used by the app
  try {
    const BluetoothDevice = Java.use('android.bluetooth.BluetoothDevice');

    function hookConnectGattOverload(ov, label) {
      ov.implementation = function () {
        // callback is usually the 3rd arg in common overloads; we’ll detect it safely.
        let cbObj = null;
        for (let i = 0; i < arguments.length; i++) {
          const a = arguments[i];
          try {
            // BluetoothGattCallback is a class type, so it will have getClass()
            if (a && a.getClass && a.getClass().getName) {
              const nm = a.getClass().getName().toString();
              if (nm.indexOf('BluetoothGattCallback') !== -1 || nm.indexOf('Gatt') !== -1) {
                // not perfect, but we’ll further filter below
              }
            }
          } catch (_) {}
        }

        // Known signature positions: (Context, boolean, BluetoothGattCallback, ...)
        try { cbObj = arguments[2]; } catch (_) { cbObj = null; }

        if (cbObj && cbObj.getClass) {
          try {
            const cbName = cbObj.getClass().getName().toString();
            // only hook if it’s actually a callback impl
            // (many callback impls are inner classes)
            console.log(`\n[GATT] connectGatt(${label}) callback_class=${cbName}`);
            hookCallbackClass(cbName);
          } catch (e) {
            console.log('[GATT] connectGatt: failed reading callback class: ' + e);
          }
        } else {
          console.log(`\n[GATT] connectGatt(${label}) callback=<unresolved>`);
        }

        return ov.apply(this, arguments);
      };
      console.log(`[+] Hooked BluetoothDevice.connectGatt ${label}`);
    }

    // Most common: connectGatt(Context, boolean, BluetoothGattCallback)
    try {
      hookConnectGattOverload(
        BluetoothDevice.connectGatt.overload(
          'android.content.Context',
          'boolean',
          'android.bluetooth.BluetoothGattCallback'
        ),
        '(Context, boolean, BluetoothGattCallback)'
      );
    } catch (e) {
      console.log('[-] No overload: connectGatt(Context, boolean, BluetoothGattCallback): ' + e);
    }

    // Common: connectGatt(Context, boolean, BluetoothGattCallback, int)
    try {
      hookConnectGattOverload(
        BluetoothDevice.connectGatt.overload(
          'android.content.Context',
          'boolean',
          'android.bluetooth.BluetoothGattCallback',
          'int'
        ),
        '(Context, boolean, BluetoothGattCallback, int)'
      );
    } catch (e) {
      // ok if absent
    }

    // Some devices: connectGatt(Context, boolean, BluetoothGattCallback, int, int)
    try {
      hookConnectGattOverload(
        BluetoothDevice.connectGatt.overload(
          'android.content.Context',
          'boolean',
          'android.bluetooth.BluetoothGattCallback',
          'int',
          'int'
        ),
        '(Context, boolean, BluetoothGattCallback, int, int)'
      );
    } catch (e) {
      // ok if absent
    }

    // Some devices: connectGatt(Context, boolean, BluetoothGattCallback, int, boolean)
    try {
      hookConnectGattOverload(
        BluetoothDevice.connectGatt.overload(
          'android.content.Context',
          'boolean',
          'android.bluetooth.BluetoothGattCallback',
          'int',
          'boolean'
        ),
        '(Context, boolean, BluetoothGattCallback, int, boolean)'
      );
    } catch (e) {
      // ok if absent
    }

  } catch (e) {
    console.log('[-] Failed hooking BluetoothDevice.connectGatt: ' + e);
  }

  console.log('[+] GATT notify/subscription + RX callback capture loaded');
  console.log('[+] Hooks loaded: DeviceEncryptManager (e/p) + GATT TX (write/read-req) + RX (base + lazy subclass discovery)');
});
