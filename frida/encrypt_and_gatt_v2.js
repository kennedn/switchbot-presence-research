// encrypt_and_gatt_v4.js
Java.perform(function () {

  // -----------------------
  // Helpers
  // -----------------------
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
      const v = ch.getValue();
      return bytesToHex(v) || "null";
    } catch (_) {}
    return "unknown";
  }

  function logBytes(tag, extra, bytes) {
    const hex = bytesToHex(bytes) || "null";
    const len = (hex !== "null") ? (hex.length / 2) : "n/a";
    console.log(`\n[${tag}] ${extra} len=${len}`);
    console.log(`  data=${hex}`);
  }

  function hookFirstExistingOverload(K, methodNames, overloadSig, implFactory) {
    for (let i = 0; i < methodNames.length; i++) {
      const name = methodNames[i];
      try {
        const m = K[name];
        if (!m) continue;
        const ov = m.overload.apply(m, overloadSig);
        ov.implementation = implFactory(ov, name);
        console.log(`[+] Hooked ${K.$className}.${name}(${overloadSig.join(", ")})`);
        return true;
      } catch (_) {}
    }
    console.log(`[-] Failed hooking ${K.$className} any of [${methodNames.join(", ")}] with (${overloadSig.join(", ")})`);
    return false;
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
            // printed
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

  hookAll('com.theswitchbot.devicemodel.compatibility.communication.DeviceEncryptManager', 'e');
  hookAll('com.theswitchbot.devicemodel.compatibility.communication.DeviceEncryptManager', 'p');

  // -----------------------
  // Android GATT hooks (TX + subscription)
  // -----------------------
  try {
    const BluetoothGatt = Java.use('android.bluetooth.BluetoothGatt');

    const ovW = BluetoothGatt.writeCharacteristic.overload('android.bluetooth.BluetoothGattCharacteristic');
    ovW.implementation = function (ch) {
      const mac = getMacFromGatt(this);
      const uuid = getUuidFromCh(ch);
      const hex = getHexFromChValue(ch);
      const len = (hex && hex !== "null" && hex !== "unknown") ? (hex.length / 2) : "n/a";
      console.log(`\n[GATT TX WRITE] mac=${mac} uuid=${uuid} len=${len}`);
      console.log(`  data=${hex}`);
      return ovW.call(this, ch);
    };
    console.log('[+] Hooked BluetoothGatt.writeCharacteristic(BluetoothGattCharacteristic)');

    try {
      const ovR = BluetoothGatt.readCharacteristic.overload('android.bluetooth.BluetoothGattCharacteristic');
      ovR.implementation = function (ch) {
        const mac = getMacFromGatt(this);
        const uuid = getUuidFromCh(ch);
        console.log(`\n[GATT TX READ-REQ] mac=${mac} uuid=${uuid}`);
        return ovR.call(this, ch);
      };
      console.log('[+] Hooked BluetoothGatt.readCharacteristic(BluetoothGattCharacteristic)');
    } catch (e) {}

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
    console.log('[-] Failed hooking BluetoothGatt: ' + e);
  }

  // -----------------------
  // WoBle hooks (TX + RX)
  // -----------------------
  try {
    const WoBleClient = Java.use('com.theswitchbot.common.ble.impl.WoBleClient');

    hookFirstExistingOverload(
      WoBleClient,
      ['i0'],
      ['[B', 'int'],
      function (ov, name) {
        return function (data, writeType) {
          logBytes('WoBleClient TX', `${name} writeType=${writeType}`, data);
          return ov.call(this, data, writeType);
        };
      }
    );

    hookFirstExistingOverload(
      WoBleClient,
      ['p0'],
      ['[B', 'int', 'com.theswitchbot.common.ble.LongAckSupport'],
      function (ov, name) {
        return function (data, writeType, longAckSupport) {
          let las = 'null';
          try { las = longAckSupport ? longAckSupport.getClass().getName().toString() : 'null'; } catch (_) {}
          logBytes('WoBleClient TX QUEUE', `${name} writeType=${writeType} longAck=${las}`, data);
          return ov.call(this, data, writeType, longAckSupport);
        };
      }
    );

    hookFirstExistingOverload(
      WoBleClient,
      ['o0'],
      ['[B'],
      function (ov, name) {
        return function (reply) {
          logBytes('WoBleClient REPLY', name, reply);
          return ov.call(this, reply);
        };
      }
    );

    hookFirstExistingOverload(
      WoBleClient,
      ['t0'],
      ['kotlin.jvm.functions.Function2'],
      function (ov, name) {
        return function (cb) {
          let cbClass = 'null';
          try { cbClass = cb ? cb.getClass().getName().toString() : 'null'; } catch (_) {}
          console.log(`\n[WoBleClient] ${name}(setNotificationCallback) cb_class=${cbClass}`);
          return ov.call(this, cb);
        };
      }
    );

  } catch (e) {
    console.log('[-] Failed setting up WoBleClient hooks: ' + e);
  }

  // WoBleGattCallback: hook U6 + t7 + u7
  try {
    const Cb = Java.use('com.theswitchbot.common.ble.impl.WoBleClient$WoBleGattCallback');

    // U6(gatt, characteristic) - likely "onCharacteristicChanged" handler in Nordic
    hookFirstExistingOverload(
      Cb,
      ['U6'],
      ['android.bluetooth.BluetoothGatt', 'android.bluetooth.BluetoothGattCharacteristic'],
      function (ov, name) {
        return function (gatt, ch) {
          const mac = getMacFromGatt(gatt);
          const uuid = getUuidFromCh(ch);
          const hex = getHexFromChValue(ch);
          const len = (hex && hex !== "null" && hex !== "unknown") ? (hex.length / 2) : "n/a";
          console.log(`\n[WoBleGattCallback RX] ${name} mac=${mac} uuid=${uuid} len=${len}`);
          console.log(`  data=${hex}`);
          return ov.call(this, gatt, ch);
        };
      }
    );

    // t7(woBleClient, woBleGattCallback, device, Data) - public static wrapper
    hookFirstExistingOverload(
      Cb,
      ['t7'],
      [
        'com.theswitchbot.common.ble.impl.WoBleClient',
        'com.theswitchbot.common.ble.impl.WoBleClient$WoBleGattCallback',
        'android.bluetooth.BluetoothDevice',
        'no.nordicsemi.android.ble.data.Data'
      ],
      function (ov, name) {
        return function (client, cb, dev, data) {
          try {
            const mac = dev ? dev.getAddress().toString() : 'unknown';
            let b = null;
            try { b = data ? data.m70964c() : null; } catch (_) {}
            logBytes('WoBleGattCallback RX', `${name} mac=${mac}`, b);
          } catch (e) {
            console.log('[WoBleGattCallback RX] error: ' + e);
          }
          return ov.call(this, client, cb, dev, data);
        };
      }
    );

    // u7(...) - private static worker (keep)
    hookFirstExistingOverload(
      Cb,
      ['u7'],
      [
        'com.theswitchbot.common.ble.impl.WoBleClient',
        'com.theswitchbot.common.ble.impl.WoBleClient$WoBleGattCallback',
        'android.bluetooth.BluetoothDevice',
        'no.nordicsemi.android.ble.data.Data'
      ],
      function (ov, name) {
        return function (client, cb, dev, data) {
          try {
            const mac = dev ? dev.getAddress().toString() : 'unknown';
            let b = null;
            try { b = data ? data.m70964c() : null; } catch (_) {}
            logBytes('WoBleGattCallback RX', `${name} mac=${mac}`, b);
          } catch (e) {
            console.log('[WoBleGattCallback RX] error: ' + e);
          }
          return ov.call(this, client, cb, dev, data);
        };
      }
    );

  } catch (e) {
    console.log('[-] Failed setting up WoBleGattCallback hooks: ' + e);
  }

  // WoBleManager: L(mac, data)
  try {
    const WoBleManager = Java.use('com.theswitchbot.common.ble.impl.WoBleManager');
    hookFirstExistingOverload(
      WoBleManager,
      ['L'],
      ['java.lang.String', '[B'],
      function (ov, name) {
        return function (mac, data) {
          logBytes('WoBleManager NOTIFY', `${name} mac=${mac}`, data);
          return ov.call(this, mac, data);
        };
      }
    );
  } catch (e) {
    console.log('[-] Failed setting up WoBleManager hook: ' + e);
  }

  // -----------------------
  // Nordic safety-net: hook any DataReceivedCallback implementor method matching (BluetoothDevice, Data)
  // -----------------------
  // This catches cases where RX bypasses WoBleClient$WoBleGattCallback helpers.
  try {
    const DataReceivedCallback = Java.use('no.nordicsemi.android.ble.callback.DataReceivedCallback');
    const impls = Java.enumerateLoadedClassesSync().filter(n => n.indexOf('com.theswitchbot') === 0 || n.indexOf('no.nordicsemi') === 0);

    let hooked = 0;
    impls.forEach(function (name) {
      try {
        const K = Java.use(name);
        if (!K || !K.class) return;
        if (!DataReceivedCallback.class.isAssignableFrom(K.class)) return;

        const ms = K.class.getDeclaredMethods();
        for (let i = 0; i < ms.length; i++) {
          const s = ms[i].toString();
          if (s.indexOf('android.bluetooth.BluetoothDevice') !== -1 && s.indexOf('no.nordicsemi.android.ble.data.Data') !== -1) {
            const mname = ms[i].getName().toString();
            if (!K[mname]) continue;

            // try to hook all overloads that match the signature
            K[mname].overloads.forEach(function (ov) {
              const args = ov.argumentTypes.map(t => t.className);
              if (args.length === 2 &&
                  args[0] === 'android.bluetooth.BluetoothDevice' &&
                  args[1] === 'no.nordicsemi.android.ble.data.Data') {

                ov.implementation = function (dev, data) {
                  let mac = 'unknown';
                  try { mac = dev ? dev.getAddress().toString() : 'unknown'; } catch (_) {}
                  let b = null;
                  try { b = data ? data.m70964c() : null; } catch (_) {}
                  logBytes('Nordic DataReceivedCallback RX', `${name}.${mname} mac=${mac}`, b);
                  return ov.call(this, dev, data);
                };
                hooked++;
              }
            });
          }
        }
      } catch (_) {}
    });

    console.log(`[+] Nordic RX safety-net: hooked DataReceivedCallback implementors=${hooked}`);
  } catch (e) {
    console.log('[-] Nordic RX safety-net not installed (ok): ' + e);
  }

  // -----------------------
  // Nordic TX chunking (already working for you)
  // -----------------------
  try {
    const WriteRequest = Java.use('no.nordicsemi.android.ble.WriteRequest');
    hookFirstExistingOverload(
      WriteRequest,
      ['U'],
      ['int'],
      function (ov, name) {
        return function (mtu) {
          const chunk = ov.call(this, mtu);
          logBytes('Nordic TX CHUNK', `${name} mtu=${mtu}`, chunk);
          return chunk;
        };
      }
    );
  } catch (e) {
    console.log('[-] Nordic chunk hook not installed (ok): ' + e);
  }

  console.log('[+] Loaded: DeviceEncryptManager + GATT TX/CFG + WoBle TX/RX (U6/t7/u7) + Nordic RX safety-net + Nordic chunking');
});
