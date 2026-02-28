Java.perform(function () {
  const Thread = Java.use('java.lang.Thread');
  const Exception = Java.use('java.lang.Exception');

  function stackHere() {
    // Java stack, not JS stack
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

  // Keep a small rolling cache: key = mac|hex, value = origin stack + timestamp
  const ORIGIN = new Map();
  const MAX = 2000;

  function putOrigin(mac, hex, where) {
    const key = `${mac}|${hex}`;
    ORIGIN.set(key, { t: Date.now(), where });
    if (ORIGIN.size > MAX) {
      // simple trim oldest-ish
      let i = 0;
      for (const k of ORIGIN.keys()) { ORIGIN.delete(k); if (++i > 200) break; }
    }
  }

  function getOrigin(mac, hex) {
    const key = `${mac}|${hex}`;
    return ORIGIN.get(key);
  }

  function shortUuid(uuidStr) {
    if (!uuidStr) return "null";
    return uuidStr.toLowerCase();
  }

  // 1) EARLY boundary: capture who asked to send this payload (this is your “originating caller”)
  try {
    const BleRWCompat = Java.use('com.theswitchbot.devicemodel.compatibility.communication.BleRWCompat');
    const ov = BleRWCompat.writeCmd.overload('java.lang.String', '[B', 'kotlin.coroutines.Continuation');
    ov.implementation = function (mac, bytes, cont) {
      const hex = bytesToHex(bytes) || "null";
      // This stack is from the call site that *initiated* the send request.
      // It’s usually what you actually want.
      const where = stackHere();
      putOrigin(mac, hex, where);
      return ov.call(this, mac, bytes, cont);
    };
    console.log('[+] Correlator: hooked BleRWCompat.writeCmd(mac, byte[], cont)');
  } catch (e) {
    console.log('[-] Failed hooking BleRWCompat.writeCmd: ' + e);
  }

  // 2) LATE boundary: when it actually hits GATT, look up origin and print it
  try {
    const BluetoothGatt = Java.use('android.bluetooth.BluetoothGatt');
    const ov = BluetoothGatt.writeCharacteristic.overload('android.bluetooth.BluetoothGattCharacteristic');
    ov.implementation = function (ch) {
      let mac = "unknown";
      let uuid = "unknown";
      let hex = "unknown";

      try {
        const dev = this.getDevice();
        if (dev) mac = dev.getAddress().toString();
      } catch (_) {}

      try {
        uuid = shortUuid(ch.getUuid().toString());
      } catch (_) {}

      try {
        const v = ch.getValue(); // byte[]
        hex = bytesToHex(v) || "null";
      } catch (_) {}

      const hit = getOrigin(mac, hex);

      console.log(`\n[GATT TX] mac=${mac} uuid=${uuid} len=${hex === "null" ? "n/a" : (hex.length/2)}`);
      console.log(`  data=${hex}`);

      if (hit) {
        console.log('  ORIGIN (captured at BleRWCompat.writeCmd):');
        console.log('' + hit.where);
      } else {
        console.log('  ORIGIN: <no match> (payload not seen at writeCmd boundary or mutated after)');
      }

      return ov.call(this, ch);
    };
    console.log('[+] Correlator: hooked BluetoothGatt.writeCharacteristic(ch)');
  } catch (e) {
    console.log('[-] Failed hooking BluetoothGatt.writeCharacteristic(ch): ' + e);
  }

  console.log('[+] Origin correlator loaded');
});

Java.perform(function () {
  const Exception = Java.use('java.lang.Exception');

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

  function safeArgToString(a) {
    if (a === null || a === undefined) return "null";
    try {
      if (Java.isArray(a) && a.$className === '[B') return `[B hex=${bytesToHex(a)}`;
      return a.toString();
    } catch (_) {
      return "[unprintable]";
    }
  }

  const GEN = new Map();
  const seen = new Set();
  let hooked = 0;

  const CG = Java.use('com.theswitchbot.device.protocol.CmdGenerator');
  const methods = CG.class.getDeclaredMethods(); // Java array

  for (let mi = 0; mi < methods.length; mi++) {
    const m = methods[mi];
    const name = m.getName();

    // skip ctor-ish / weird
    if (name === '<init>') continue;

    // if Frida can't resolve it as a property, skip
    if (!CG[name]) continue;

    const overloads = CG[name].overloads;
    for (let oi = 0; oi < overloads.length; oi++) {
      const ov = overloads[oi];

      const sig = name + "(" + ov.argumentTypes.map(t => t.className).join(",") + ")->" + ov.returnType.className;
      if (seen.has(sig)) continue;
      seen.add(sig);

      const ret = ov.returnType.className;
      const isByteArray = (ret === '[B');
      const isByteArrayArray = (ret === '[[B');
      if (!isByteArray && !isByteArrayArray) continue;

      hooked++;

      ov.implementation = function () {
        const args = arguments;
        const argDump = [];
        for (let i = 0; i < args.length; i++) argDump.push(safeArgToString(args[i]));

        const out = ov.apply(this, args);

        if (isByteArray) {
          const hex = bytesToHex(out);
          const meta = { meth: `CmdGenerator.${name}`, args: argDump, stack: stackHere(), t: Date.now() };
          GEN.set(hex, meta);

          console.log(`\n[CMDGEN] ${meta.meth}`);
          console.log(`  out_len=${out ? out.length : "n/a"} hex=${hex}`);
          console.log(`  args=${JSON.stringify(argDump)}`);
        } else {
          try {
            // out is byte[][]
            for (let j = 0; j < out.length; j++) {
              const hex = bytesToHex(out[j]);
              const meta = { meth: `CmdGenerator.${name}[${j}]`, args: argDump, stack: stackHere(), t: Date.now() };
              GEN.set(hex, meta);

              console.log(`\n[CMDGEN] ${meta.meth}`);
              console.log(`  out_len=${out[j] ? out[j].length : "n/a"} hex=${hex}`);
              console.log(`  args=${JSON.stringify(argDump)}`);
            }
          } catch (e) {
            console.log(`\n[CMDGEN] CmdGenerator.${name} -> [[B (iter fail): ${e}]`);
          }
        }

        return out;
      };
    }
  }

  console.log(`[+] CmdGenerator hooks installed. hooked_overloads=${hooked}`);
  globalThis.__cmdgen_cache__ = GEN;
});
