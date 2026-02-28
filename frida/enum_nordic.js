'use strict';

Java.perform(function () {
  function dumpClass(name) {
    try {
      const C = Java.use(name);
      console.log('\n===== ' + name + ' =====');

      // Declared methods (best for obfuscated builds)
      const jklass = C.class;
      const methods = jklass.getDeclaredMethods();
      console.log('Declared methods: ' + methods.length);
      for (let i = 0; i < methods.length; i++) {
        console.log('  ' + methods[i].toString());
      }

      // Frida-visible members (sometimes includes overload info)
      const keys = Object.keys(C).sort();
      console.log('Frida-visible keys: ' + keys.length);
      keys.slice(0, 200).forEach(k => console.log('  ' + k));
      if (keys.length > 200) console.log('  ... (truncated)');

      C.$dispose();
    } catch (e) {
      console.log('[-] dumpClass failed for ' + name + ': ' + e);
    }
  }

  // 1) Dump the app callback class you pasted
  dumpClass('com.theswitchbot.common.ble.impl.WoBleClient$WoBleGattCallback');

  // 2) Find likely Nordic BleManager classes actually loaded
  const hits = [];
  Java.enumerateLoadedClasses({
    onMatch: function (name) {
      if (name.startsWith('no.nordicsemi.android.ble') && name.toLowerCase().includes('blemanager')) {
        hits.push(name);
      }
      // Sometimes the ktx artifact relocates packages; catch any “nordicsemi” too
      if (name.toLowerCase().includes('nordicsemi') && name.toLowerCase().includes('blemanager')) {
        hits.push(name);
      }
    },
    onComplete: function () {
      const uniq = Array.from(new Set(hits)).sort();
      console.log('\n===== BleManager-ish loaded classes: ' + uniq.length + ' =====');
      uniq.forEach(n => console.log('  ' + n));

      // Dump a few of them in detail (up to 10 to avoid spam)
      uniq.slice(0, 10).forEach(dumpClass);

      console.log('\n[+] Enumeration complete.');
    }
  });
});
