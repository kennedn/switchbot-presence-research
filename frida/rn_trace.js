'use strict';

function cstr(p) { return p.isNull() ? '' : p.readCString(); }
function bt(ctx) {
  return Thread.backtrace(ctx, Backtracer.FUZZY)
    .map(DebugSymbol.fromAddress)
    .join('\n');
}

function hookWhenReady() {
  let m;
  try { m = Process.getModuleByName('libreactnativejni.so'); }
  catch (e) { return false; }

  const exp = m.enumerateExports().find(e => e.name === 'fb_printLog');
  if (!exp) { console.log('[-] fb_printLog not found'); return true; }

  Interceptor.attach(exp.address, {
    onEnter(args) {
      // Dump first 8 args as potential strings to see if stack is included
      const ss = [];
      for (let i = 0; i < 8; i++) {
        try {
          const s = cstr(args[i]);
          if (s && s.length) ss.push(`[${i}] ${s}`);
        } catch (e) {}
      }
      const joined = ss.join(' | ');
      if (joined.indexOf('settingUnattendedTimeout') === -1 && joined.indexOf('Unattended') === -1) return;

      console.log('\n[fb_printLog args] ' + joined);
      console.log('[BT]\n' + bt(this.context));
    }
  });

  console.log('[+] Hooked fb_printLog @ ' + exp.address);
  return true;
}

const t = setInterval(function () {
  if (hookWhenReady()) clearInterval(t);
}, 200);

console.log('[*] Waiting for libreactnativejni.so...');
