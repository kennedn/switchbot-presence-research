'use strict';

Java.perform(function () {

  function hex(bytes) {
    if (!bytes) return "null";
    const arr = Java.array('byte', bytes);
    let s = '';
    for (let i = 0; i < arr.length; i++) {
      let v = arr[i];
      if (v < 0) v += 256;
      s += ('0' + v.toString(16)).slice(-2);
    }
    return s;
  }

  function argInfo(a) {
    if (a === null || a === undefined)
      return { t: String(a), v: String(a) };

    try {
      if (a.$className === '[B') {
        const len = Java.array('byte', a).length;
        return { t: '[B', v: `len=${len} hex=${hex(a)}` };
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
      if (!Pair.class.isInstance(obj))
        return false;

      const first = obj.getFirst();
      const second = obj.getSecond();

      console.log(`  RET Pair.first: ${first}`);

      if (second && second.$className === '[B') {
        const len = Java.array('byte', second).length;
        console.log(`  RET Pair.second: [B len=${len} hex=${hex(second)}`);
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
            console.log(`  RET: [B len=${len} hex=${hex(ret)}`);
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

  hookAll(
    'com.theswitchbot.devicemodel.compatibility.communication.BleRWCompat',
    'writeCmd'
  );

  console.log('[+] Encryption/Write hooks loaded');
});

Java.perform(function () {
  const Exception = Java.use('java.lang.Exception');

  function hex(bytes) {
    if (!bytes) return '';
    const arr = Java.array('byte', bytes);
    let out = '';
    for (let i = 0; i < arr.length; i++) out += ('0' + ((arr[i] & 0xff).toString(16))).slice(-2);
    return out;
  }

  function stack() {
    try {
      const st = Exception.$new().getStackTrace();
      let s = '';
      for (let i = 4; i < st.length; i++) {
        const line = st[i].toString();
        if (line.indexOf('frida') !== -1) continue;
        s += '    at ' + line + '\n';
      }
      return s;
    } catch (e) {
      return '    <stack failed: ' + e + '>\n';
    }
  }

  // ------------------------------------------------------------
  // Framework choke points (TX + notification enable)
  // ------------------------------------------------------------
  try {
      const BluetoothGatt = Java.use('android.bluetooth.BluetoothGatt');

        const wc = BluetoothGatt.writeCharacteristic.overload('android.bluetooth.BluetoothGattCharacteristic');
        wc.implementation = function (ch) {
          const dev = this.getDevice();
          const mac = dev ? dev.getAddress() : '<no-device>';
          const uuid = ch ? ch.getUuid().toString() : '<no-ch>';
          let v = null;
          try { v = ch.getValue(); } catch (_) {}
          console.log('\n[GATT TX] mac=' + mac + ' uuid=' + uuid + ' len=' + (v ? v.length : 0));
          console.log('  data=' + hex(v));
          return wc.call(this, ch); // <-- call original
        };

        const scn = BluetoothGatt.setCharacteristicNotification
          .overload('android.bluetooth.BluetoothGattCharacteristic', 'boolean');
        scn.implementation = function (ch, enable) {
          const dev = this.getDevice();
          const mac = dev ? dev.getAddress() : '<no-device>';
          const uuid = ch ? ch.getUuid().toString() : '<no-ch>';
          console.log('\n[GATT NOTIFY] mac=' + mac + ' uuid=' + uuid + ' enable=' + enable);
          return scn.call(this, ch, enable); // <-- call original
        };

        const wd = BluetoothGatt.writeDescriptor
          .overload('android.bluetooth.BluetoothGattDescriptor');
        wd.implementation = function (desc) {
          const dev = this.getDevice();
          const mac = dev ? dev.getAddress() : '<no-device>';
          const uuid = desc ? desc.getUuid().toString() : '<no-desc>';
          let v = null;
          try { v = desc.getValue(); } catch (_) {}
          console.log('\n[GATT DESC WRITE] mac=' + mac + ' descUuid=' + uuid + ' len=' + (v ? v.length : 0));
          console.log('  data=' + hex(v));
          return wd.call(this, desc); // <-- call original
        };

    console.log('[+] Hooked BluetoothGatt.writeCharacteristic / setCharacteristicNotification / writeDescriptor');
  } catch (e) {
    console.log('[-] Framework hook error: ' + e);
  }

  // ------------------------------------------------------------
  // Hook *all* loaded BluetoothGattCallback implementations
  // (this is the key fix for RX)
  // ------------------------------------------------------------
  function hookIfPresent(className) {
    try {
      const C = Java.use(className);

      // RX notifications/indications (old API)
      if (C.onCharacteristicChanged) {
        const ovs = C.onCharacteristicChanged.overloads;
        for (let i = 0; i < ovs.length; i++) {
          const ov = ovs[i];
          if (ov.argumentTypes.length === 2) {
            ov.implementation = function (gatt, ch) {
              const dev = gatt ? gatt.getDevice() : null;
              const mac = dev ? dev.getAddress() : '<no-device>';
              const uuid = ch ? ch.getUuid().toString() : '<no-ch>';
              let v = null;
              try { v = ch.getValue(); } catch (_) {}
              console.log('\n[CB RX] ' + className + ' mac=' + mac + ' uuid=' + uuid + ' len=' + (v ? v.length : 0));
              console.log('  data=' + hex(v));
              return ov.call(this, gatt, ch);
            };
            console.log('[+] Hooked ' + className + '.onCharacteristicChanged(gatt, ch)');
          }
        }
      }

      // TX result callback (very useful)
      if (C.onCharacteristicWrite) {
        const ovs = C.onCharacteristicWrite.overloads;
        for (let i = 0; i < ovs.length; i++) {
          const ov = ovs[i];
          if (ov.argumentTypes.length === 3) {
            ov.implementation = function (gatt, ch, status) {
              const dev = gatt ? gatt.getDevice() : null;
              const mac = dev ? dev.getAddress() : '<no-device>';
              const uuid = ch ? ch.getUuid().toString() : '<no-ch>';
              console.log('\n[CB WRITE] ' + className + ' mac=' + mac + ' uuid=' + uuid + ' status=' + status);
              return ov.call(this, gatt, ch, status);
            };
            console.log('[+] Hooked ' + className + '.onCharacteristicWrite(gatt, ch, status)');
          }
        }
      }

      // Descriptor write results (often CCCD)
      if (C.onDescriptorWrite) {
        const ovs = C.onDescriptorWrite.overloads;
        for (let i = 0; i < ovs.length; i++) {
          const ov = ovs[i];
          if (ov.argumentTypes.length === 3) {
            ov.implementation = function (gatt, desc, status) {
              const dev = gatt ? gatt.getDevice() : null;
              const mac = dev ? dev.getAddress() : '<no-device>';
              const uuid = desc ? desc.getUuid().toString() : '<no-desc>';
              console.log('\n[CB DESC WRITE] ' + className + ' mac=' + mac + ' descUuid=' + uuid + ' status=' + status);
              return ov.call(this, gatt, desc, status);
            };
            console.log('[+] Hooked ' + className + '.onDescriptorWrite(gatt, desc, status)');
          }
        }
      }
    } catch (_) {
      // ignore
    }
  }

  Java.enumerateLoadedClasses({
    onMatch: function (name) {
      // Fast filter to reduce work; you can loosen if needed
      if (name.indexOf('switchbot') !== -1 ||
          name.indexOf('theswitchbot') !== -1 ||
          name.indexOf('nordicsemi') !== -1 ||
          name.indexOf('ble') !== -1) {
        hookIfPresent(name);
      }
    },
    onComplete: function () {
      console.log('[+] Callback enumeration complete');
    }
  });

  console.log('[+] BLE hooks loaded');
});
