// hook_WoSensorDevice_Companion_m51993c.js
// Frida 17.x — hooks WoSensorDevice$Companion.c(...) which is m51993c in your decompilation.
// Also hooks the synthetic wrapper d(...) (m51991d) because Kotlin default-args calls often go through it.

'use strict';

function bytesToHex(bArr) {
  if (!bArr) return 'null';
  const n = bArr.length;
  const out = [];
  for (let i = 0; i < n; i++) {
    let v = bArr[i];
    if (v < 0) v += 256;
    out.push(('0' + v.toString(16)).slice(-2));
  }
  return out.join(' ');
}

function bytesToDec(bArr) {
  if (!bArr) return 'null';
  const n = bArr.length;
  const out = [];
  for (let i = 0; i < n; i++) out.push('' + bArr[i]);
  return out.join(',');
}

function safeStr(x) {
  try {
    if (x === null || x === undefined) return 'null';
    return x.toString();
  } catch (e) {
    return `<toString() threw: ${e}>`;
  }
}

function stackCsv() {
  try {
    const Exception = Java.use('java.lang.Exception');
    const e = Exception.$new();
    const st = e.getStackTrace();
    const n = st.length;
    const parts = [];
    for (let i = 0; i < n; i++) parts.push(st[i].toString());
    return parts.join(',');
  } catch (_) {
    return '<stack unavailable>';
  }
}

function printPhysicalDevice(pd) {
  if (!pd) {
    console.log('  device: null');
    return;
  }
  console.log('  device: ' + safeStr(pd));
  // These method names are from your logs; guard each in case of obfuscation differences.
  try { console.log('  deviceMac: ' + safeStr(pd.getDeviceMac())); } catch (_) {}
  try { console.log('  uniqueId: ' + safeStr(pd.uniqueId())); } catch (_) {}
  try { console.log('  deviceType: ' + safeStr(pd.getDeviceType())); } catch (_) {}
  try { console.log('  bleVersion: ' + safeStr(pd.getBleVersion())); } catch (_) {}
}

Java.perform(function () {
  const CLS = 'com.theswitchbot.device.impl.motionsensor.device.WoSensorDevice$Companion';
  let Companion;
  try {
    Companion = Java.use(CLS);
  } catch (e) {
    console.log('[-] Could not load ' + CLS + ': ' + e);
    return;
  }

  console.log('[+] Loaded ' + CLS);

  // Hook: public final Object c(byte[] cmd, PhysicalDevice device, CmdConnectType type, Continuation cont)
  try {
    const cOv = Companion.c.overload(
      '[B',
      'com.theswitchbot.device.abs.type.PhysicalDevice',
      'com.theswitchbot.device.control.CmdConnectType',
      'kotlin.coroutines.Continuation'
    );

    cOv.implementation = function (cmd, device, cmdConnectType, cont) {
      console.log('\n=== WoSensorDevice$Companion.c (m51993c) ===');
      printPhysicalDevice(device);

      try {
        if (cmd) {
          console.log('  cmd_len: ' + cmd.length);
          console.log('  cmd_hex: ' + bytesToHex(cmd));
          console.log('  cmd_dec: ' + bytesToDec(cmd));
        } else {
          console.log('  cmd: null');
        }
      } catch (e) {
        console.log('  [!] cmd print failed: ' + e);
      }

      console.log('  cmdConnectType: ' + safeStr(cmdConnectType));
      console.log('  cont: ' + safeStr(cont));
      console.log('  stack: ' + stackCsv());

      // IMPORTANT: use apply(this, arguments) to avoid bridge issues
      const ret = cOv.apply(this, arguments);

      console.log('  => return: ' + safeStr(ret));
      // If it returns CmdResult sometimes, you can print reply bytes
      try {
        if (ret && ret.getReply) {
          const reply = ret.getReply();
          console.log('  => reply_len: ' + (reply ? reply.length : 'null'));
          console.log('  => reply_hex: ' + bytesToHex(reply));
          console.log('  => reply_dec: ' + bytesToDec(reply));
        }
      } catch (_) {}

      return ret;
    };

    console.log('[+] Hooked ' + CLS + '.c([B, PhysicalDevice, CmdConnectType, Continuation)');
  } catch (e) {
    console.log('[-] Failed hooking c/m51993c: ' + e);
  }

  // Hook: public static Object d(Companion, byte[], PhysicalDevice, CmdConnectType, Continuation, int, Object)
  // This is the Kotlin default-args synthetic wrapper (m51991d in your decompilation).
  try {
    const dOv = Companion.d.overload(
      CLS,
      '[B',
      'com.theswitchbot.device.abs.type.PhysicalDevice',
      'com.theswitchbot.device.control.CmdConnectType',
      'kotlin.coroutines.Continuation',
      'int',
      'java.lang.Object'
    );

    dOv.implementation = function (selfCompanion, cmd, device, cmdConnectType, cont, mask, marker) {
      console.log('\n=== WoSensorDevice$Companion.d (synthetic wrapper -> m51993c) ===');
      console.log('  mask: ' + mask + '  marker: ' + safeStr(marker));
      printPhysicalDevice(device);
      try {
        if (cmd) {
          console.log('  cmd_len: ' + cmd.length);
          console.log('  cmd_hex: ' + bytesToHex(cmd));
        } else {
          console.log('  cmd: null');
        }
      } catch (_) {}
      console.log('  cmdConnectType: ' + safeStr(cmdConnectType));
      console.log('  stack: ' + stackCsv());

      const ret = dOv.apply(this, arguments);

      console.log('  => return: ' + safeStr(ret));
      return ret;
    };

    console.log('[+] Hooked ' + CLS + '.d(Companion,[B,PhysicalDevice,CmdConnectType,Continuation,int,Object)');
  } catch (e) {
    console.log('[-] Failed hooking d/m51991d: ' + e);
  }

  console.log('[+] Done.');
});
