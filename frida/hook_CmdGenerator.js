// hook_CmdGenerator.js
//
// Logs *all* calls into com.theswitchbot.device.protocol.CmdGenerator (all overloads):
//  - method name + signature
//  - args (special handling for byte[] and byte[][])
//  - caller (first non-Frida frame)
//  - full Java stack (optional; toggle below)
//  - return value (special handling for byte[] and byte[][])
//
// Run:
//   frida -U -f com.theswitchbot.switchbot -l hook_CmdGenerator.js
//
// Tip: Once you're happy it's working, re-enable the NOISY filter (d0 etc) to reduce spam.

'use strict';

const CFG = {
  showFullStack: false,          // true = print full stack, false = only "Caller:"
  maxBytesToPrint: 256,         // truncate long byte arrays
  max2dRowsToPrint: 32,         // truncate byte[][] rows
  // If non-empty: only log these method names
  onlyNames: new Set([
    // e.g. 'd0', 'd2'
  ]),
  // If non-empty: skip these method names
  skipNames: new Set([
    // e.g. 'd0'
  ]),
};

function pad2(n) { return (n & 0xff).toString(16).padStart(2, '0'); }

function bytesToHexAndDec(jsBytes) {
  const n = jsBytes.length;
  const limit = Math.min(n, CFG.maxBytesToPrint);
  const hex = [];
  const dec = [];
  for (let i = 0; i < limit; i++) {
    const b = jsBytes[i];
    hex.push(pad2(b));
    dec.push(b);
  }
  const suffix = n > limit ? ` ... (+${n - limit})` : '';
  return {
    hex: `[${hex.join(' ')}]${suffix}`,
    dec: `[${dec.join(',')}]${suffix}`,
    len: n,
  };
}

function isJavaByteArray(obj) {
  if (!obj) return false;
  // Fast path: Frida Java arrays expose $className like "[B"
  try {
    return obj.$className === '[B';
  } catch (_) { return false; }
}

function isJavaByteArray2D(obj) {
  if (!obj) return false;
  try {
    return obj.$className === '[[B';
  } catch (_) { return false; }
}

function toJsByteArray(javaByteArray) {
  // Returns JS numbers -128..127
  const arr = Java.array('byte', javaByteArray);
  // Java.array already returns a JS array-like; convert to real JS array
  return Array.prototype.slice.call(arr);
}

function formatAny(arg) {
  if (arg === null || arg === undefined) return 'null';

  // Handle byte[]
  if (isJavaByteArray(arg)) {
    const jsBytes = toJsByteArray(arg);
    const info = bytesToHexAndDec(jsBytes);
    return `byte[](${info.len}) hex=${info.hex} dec=${info.dec}`;
  }

  // Handle byte[][]
  if (isJavaByteArray2D(arg)) {
    const rows = Java.array('[B', arg); // array of byte[]
    const rowCount = rows.length;
    const limit = Math.min(rowCount, CFG.max2dRowsToPrint);
    let out = `byte[][](${rowCount})`;
    for (let i = 0; i < limit; i++) {
      const row = rows[i];
      if (row === null) {
        out += `\n    [${i}]: null`;
      } else {
        const jsBytes = toJsByteArray(row);
        const info = bytesToHexAndDec(jsBytes);
        out += `\n    [${i}]: byte[](${info.len}) hex=${info.hex} dec=${info.dec}`;
      }
    }
    if (rowCount > limit) out += `\n    ... (+${rowCount - limit} more rows)`;
    return out;
  }

  // Primitives / boxed
  const t = typeof arg;
  if (t === 'number' || t === 'boolean' || t === 'string') return `${t}: ${arg}`;

  // Java objects
  try {
    // Some objects are Java wrappers; print class + toString
    const cls = arg.getClass ? arg.getClass().getName() : (arg.$className || 'Object');
    let s;
    try { s = arg.toString(); } catch (_) { s = '<toString() threw>'; }
    return `${cls}: ${s}`;
  } catch (_) {
    // Fallback
    return `object: ${String(arg)}`;
  }
}

function getStack(exceptionCls) {
  const e = exceptionCls.$new();
  const stack = e.getStackTrace(); // StackTraceElement[]
  const lines = [];
  for (let i = 0; i < stack.length; i++) {
    lines.push('        at ' + stack[i].toString());
  }
  return lines;
}

function firstUsefulCallerLine(stackLines) {
  // Pick first stack frame that is not:
  // - CmdGenerator.* (we want the caller of CmdGenerator)
  // - java.lang.*, dalvik.*, com.android.*, android.*
  for (let i = 0; i < stackLines.length; i++) {
    const l = stackLines[i];
    if (l.includes('com.theswitchbot.device.protocol.CmdGenerator.')) continue;
    if (l.includes('java.lang.')) continue;
    if (l.includes('dalvik.')) continue;
    if (l.includes('com.android.')) continue;
    if (l.includes('android.')) continue;
    if (l.includes('kotlin.')) continue;
    if (l.includes('kotlinx.')) continue;
    return l.trim().replace(/^at\s+/, '').replace(/^at\s+/, '');
  }
  return '(unknown)';
}

Java.perform(function () {
  const clsName = 'com.theswitchbot.device.protocol.CmdGenerator';
  const CmdGenerator = Java.use(clsName);
  const ExceptionCls = Java.use('java.lang.Exception');

  const methods = CmdGenerator.class.getDeclaredMethods();
  const methodNames = new Set();
  for (let i = 0; i < methods.length; i++) {
    methodNames.add(methods[i].getName());
  }

  let hooked = 0;

  methodNames.forEach(function (name) {
    if (CFG.onlyNames.size > 0 && !CFG.onlyNames.has(name)) return;
    if (CFG.skipNames.size > 0 && CFG.skipNames.has(name)) return;

    // Frida exposes methods as properties on the Java.use() wrapper
    // Some declared methods may not be accessible by that simple name (rare), so guard.
    if (!CmdGenerator[name]) return;

    const overloads = CmdGenerator[name].overloads;
    for (let oi = 0; oi < overloads.length; oi++) {
      const ov = overloads[oi];

      const retType = ov.returnType ? ov.returnType.className : '?';
      const argTypes = ov.argumentTypes ? ov.argumentTypes.map(t => t.className).join(', ') : '?';
      const signature = `${clsName}.${name}(${argTypes}) : ${retType}`;

      const original = ov.implementation;
      ov.implementation = function () {
        try {
          console.log(`\n=== ${signature} ===`);

          // args
          for (let ai = 0; ai < arguments.length; ai++) {
            console.log(`  arg${ai}: ${formatAny(arguments[ai])}`);
          }

          // stack
          const stackLines = getStack(ExceptionCls);
          const caller = firstUsefulCallerLine(stackLines);

          console.log(`  Caller: ${caller}`);
          if (CFG.showFullStack) {
            console.log('  Stack:');
            for (let i = 0; i < stackLines.length; i++) console.log(stackLines[i]);
          }

          // call original
          const ret = ov.apply(this, arguments);

          // return
          if (retType === 'void') {
            console.log('  => return: void');
          } else {
            console.log(`  => return: ${formatAny(ret)}`);
          }

          return ret;
        } catch (e) {
          console.log(`[!] Error in hook for ${signature}: ${e}`);
          // Fallback to original if something goes wrong
          return ov.apply(this, arguments);
        }
      };

      hooked++;
    }
  });

  console.log(`[+] Hooked ${clsName}: ${hooked} overloads (${methodNames.size} unique method names).`);
});
