'use strict';

Java.perform(function () {
  const Handler = Java.use('no.nordicsemi.android.ble.BleManagerHandler');
  const Exception = Java.use('java.lang.Exception');

  function hex(bytes) {
    if (!bytes) return '';
    const arr = Java.array('byte', bytes);
    let out = '';
    for (let i = 0; i < arr.length; i++) {
      const b = arr[i] & 0xff;
      out += ('0' + b.toString(16)).slice(-2);
    }
    return out;
  }

  function shortStack() {
    try {
      const st = Exception.$new().getStackTrace();
      let s = '';
      // skip first few frames inside Frida/our hook
      for (let i = 4; i < Math.min(st.length, 18); i++) {
        const line = st[i].toString();
        // keep it readable; you can remove filters if you want everything
        if (line.indexOf('frida') !== -1) continue;
        s += '    at ' + line + '\n';
      }
      return s;
    } catch (e) {
      return '    <stack failed: ' + e + '>\n';
    }
  }

  function getDeviceSafe(self) {
    try {
      // BleManagerHandler.k3(): BluetoothDevice
      const dev = self.k3();
      if (dev) return dev;
    } catch (_) {}
    return null;
  }

  // =========================
  // RX: notifications/indications -> Z2(characteristic, byte[])
  // =========================
  try {
    Handler.Z2.overload('android.bluetooth.BluetoothGattCharacteristic', '[B').implementation =
      function (ch, data) {
        const dev = getDeviceSafe(this);
        const mac = dev ? dev.getAddress() : '<no-device>';
        const uuid = ch ? ch.getUuid().toString() : '<no-ch>';
        const h = hex(data);

        console.log('\n[BLE RX] mac=' + mac + ' uuid=' + uuid + ' len=' + (data ? data.length : 0));
        console.log('  data=' + h);
        //console.log('  stack:\n' + shortStack());

        return this.Z2(ch, data);
      };

    console.log('[+] Hooked BleManagerHandler.Z2(RX notify/indication)');
  } catch (e) {
    console.log('[-] Failed hooking BleManagerHandler.Z2: ' + e);
  }

  // =========================
  // TX: write attempt -> b3(device, characteristic, byte[]) : boolean
  // (this is a very common internal “doWrite” gate in Nordic)
  // =========================
  try {
    Handler.b3.overload('android.bluetooth.BluetoothDevice', 'android.bluetooth.BluetoothGattCharacteristic', '[B')
      .implementation = function (dev, ch, data) {
        const mac = dev ? dev.getAddress() : '<no-device>';
        const uuid = ch ? ch.getUuid().toString() : '<no-ch>';
        const h = hex(data);

        console.log('\n[BLE TX] mac=' + mac + ' uuid=' + uuid + ' len=' + (data ? data.length : 0));
        console.log('  data=' + h);
        //console.log('  stack:\n' + shortStack());

        return this.b3(dev, ch, data);
      };

    console.log('[+] Hooked BleManagerHandler.b3(TX write attempt)');
  } catch (e) {
    console.log('[-] Failed hooking BleManagerHandler.b3: ' + e);
  }

  // Optional: if the app uses these Data-based paths, log them too.
  // L6(device, Data) and j4(device, Data) exist in your dump.
  function hookDataMethod(name) {
    try {
      Handler[name].overload('android.bluetooth.BluetoothDevice', 'no.nordicsemi.android.ble.data.Data')
        .implementation = function (dev, dataObj) {
          const mac = dev ? dev.getAddress() : '<no-device>';
          let bytes = null;
          try { bytes = dataObj ? dataObj.getValue() : null; } catch (_) {}
          console.log('\n[BLE ' + name + '] mac=' + mac + ' data=' + hex(bytes));
          console.log('  stack:\n' + shortStack());
          return this[name](dev, dataObj);
        };
      console.log('[+] Hooked BleManagerHandler.' + name + '(device, Data)');
    } catch (e) {
      console.log('[-] Failed hooking BleManagerHandler.' + name + ': ' + e);
    }
  }

  hookDataMethod('L6');
  hookDataMethod('j4');

  console.log('[+] Nordic BLE hooks v2 loaded');
});
