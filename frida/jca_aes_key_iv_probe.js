/**
 * jca_ctr_key_iv_dofinal_nodedupe.js
 *
 * No dedupe:
 *  - Prints AES key every time SecretKeySpec([B,"AES") is created (filtered to DeviceCTRCipher path)
 *  - Prints IV every time IvParameterSpec([B) is created (filtered to DeviceCTRCipher path)
 *  - Prints doFinal IN/OUT for AES/CTR/NoPadding (filtered to DeviceCTRCipher path)
 */

Java.perform(function () {
  const Cipher = Java.use('javax.crypto.Cipher');
  const SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
  const IvParameterSpec = Java.use('javax.crypto.spec.IvParameterSpec');
  const Exception = Java.use('java.lang.Exception');

  function bytesToHex(barr, maxBytes) {
    if (!barr) return "null";
    let a;
    try { a = Java.array('byte', barr); } catch (_) { return "<?>"; }
    const limit = maxBytes ? Math.min(a.length, maxBytes) : a.length;
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

  function stackHasInteresting() {
    try {
      const st = Exception.$new().getStackTrace();
      const n = Math.min(st.length, 18);
      for (let i = 0; i < n; i++) {
        const s = st[i].toString();
        if (
          s.indexOf('com.theswitchbot.device.protocol.security.base.DeviceCTRCipher') !== -1 ||
          s.indexOf('com.theswitchbot.rn.nativeModule.WoPropertyModule.ctrEncryData') !== -1
        ) return true;
      }
    } catch (_) {}
    return false;
  }

  // KEY: SecretKeySpec([B, "AES")
  try {
    const sk = SecretKeySpec.$init.overload('[B', 'java.lang.String');
    sk.implementation = function (keyBytes, algo) {
      const algoStr = algo ? algo.toString() : "null";
      if (algoStr === "AES" && stackHasInteresting()) {
        console.log(`\n[JCA KEY] SecretKeySpec algo=AES len=${bytesLen(keyBytes)} key=${bytesToHex(keyBytes, 64)}`);
      }
      return sk.call(this, keyBytes, algo);
    };
    console.log('[+] Hooked SecretKeySpec.<init>([B,String) filtered (NO DEDUPE)');
  } catch (e) {
    console.log('[-] SecretKeySpec hook failed: ' + e);
  }

  // IV: IvParameterSpec([B)
  try {
    const iv = IvParameterSpec.$init.overload('[B');
    iv.implementation = function (ivBytes) {
      if (stackHasInteresting()) {
        console.log(`\n[JCA IV] IvParameterSpec len=${bytesLen(ivBytes)} iv=${bytesToHex(ivBytes, 64)}`);
      }
      return iv.call(this, ivBytes);
    };
    console.log('[+] Hooked IvParameterSpec.<init>([B) filtered (NO DEDUPE)');
  } catch (e) {
    console.log('[-] IvParameterSpec hook failed: ' + e);
  }

  // doFinal([B) for AES/CTR/NoPadding
  try {
    const df = Cipher.doFinal.overload('[B');
    df.implementation = function (input) {
      let alg = "<?>"; 
      try { alg = this.getAlgorithm().toString(); } catch (_) {}

      if (alg !== "AES/CTR/NoPadding") return df.call(this, input);
      if (!stackHasInteresting()) return df.call(this, input);

      console.log(`\n[CTR] doFinal alg=${alg}`);
      console.log(`  IN  len=${bytesLen(input)} hex=${bytesToHex(input, 128)}`);

      const out = df.call(this, input);

      console.log(`  OUT len=${bytesLen(out)} hex=${bytesToHex(out, 128)}`);
      return out;
    };
    console.log('[+] Hooked Cipher.doFinal([B) filtered (NO DEDUPE)');
  } catch (e) {
    console.log('[-] Cipher.doFinal hook failed: ' + e);
  }

  console.log('[+] Loaded: filtered key + iv + CTR doFinal hooks (NO DEDUPE)');
});
