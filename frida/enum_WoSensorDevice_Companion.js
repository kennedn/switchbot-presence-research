// enum_WoSensorDevice_Companion.js
'use strict';

Java.perform(function () {
  const name = 'com.theswitchbot.device.impl.motionsensor.device.WoSensorDevice$Companion';

  let C;
  try {
    C = Java.use(name);
    console.log('[+] Loaded ' + name);
  } catch (e) {
    console.log('[-] Failed to load ' + name + ': ' + e);
    return;
  }

  const declared = C.class.getDeclaredMethods();
  console.log('[+] Declared methods: ' + declared.length);

  // Print raw reflected signatures (authoritative)
  for (let i = 0; i < declared.length; i++) {
    try {
      console.log('  ' + declared[i].toString());
    } catch (e) {
      console.log('  <err printing method ' + i + '> ' + e);
    }
  }

  // Print Frida-visible members (what you can hook)
  console.log('\n[+] Frida-visible keys on wrapper:');
  const keys = Object.keys(C).sort();
  for (let i = 0; i < keys.length; i++) {
    const k = keys[i];
    if (k === '$new' || k === 'class' || k === '$className' || k === '$dispose') continue;
    try {
      const v = C[k];
      if (v && typeof v.overloads !== 'undefined') {
        console.log('  ' + k + '  (overloads=' + v.overloads.length + ')');
        v.overloads.forEach(function (ov, idx) {
          console.log('    [' + idx + '] ' + k + '(' + ov.argumentTypes.map(t => t.className).join(', ') + ') -> ' + ov.returnType.className);
        });
      }
    } catch (_) {}
  }

  console.log('\n[+] Done.');
});
