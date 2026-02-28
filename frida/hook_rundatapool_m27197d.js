// hook_chain_from_getrundata_compact.js
'use strict';

Java.perform(function () {
  const Parser = Java.use('com.theswitchbot.device.protocol.scan.delegate.WoPresenceProParser');

  const hookedClasses = {}; // className -> true

  // Per-object aggregation: use object identity hash as key (stable enough for runtime)
  const System = Java.use('java.lang.System');
  const agg = new Map(); // key -> { dt, vt, vals: [], lastTs }

  // === knobs ===
  const PRINT_ON = 'setValueType'; // 'setValueType' is usually the "commit" moment
  const DROP_DEFAULTS = true;      // reduce noise
  const DEFAULT_SET = new Set(['i=0', 'b=false', 'l=0', 'f=0.0', 's=""', 'a=null']);
  // ============

  function keyFor(obj) {
    // identityHashCode avoids relying on toString()
    return '' + System.identityHashCode(obj);
  }

  function getOrInit(obj) {
    const k = keyFor(obj);
    let s = agg.get(k);
    if (!s) {
      s = { dt: '?', vt: '?', vals: [] };
      agg.set(k, s);
    }
    return { k, s };
  }

  function fmtLine(state) {
    // dt, vt, then values
    const parts = [];
    if (state.dt && state.dt !== '?') parts.push(state.dt);
    if (state.vt && state.vt !== '?') parts.push('vt=' + state.vt);
    if (state.vals.length) parts.push(state.vals.join(', '));
    return parts.join(', ');
  }

  function maybeAddVal(state, token) {
    if (DROP_DEFAULTS && DEFAULT_SET.has(token)) return;
    // keep last write of each value kind (i/b/l/f/s/a) and avoid repeats
    const kind = token.slice(0, 1); // i b l f s a
    for (let i = state.vals.length - 1; i >= 0; i--) {
      if (state.vals[i].slice(0, 1) === kind) {
        state.vals[i] = token;
        return;
      }
    }
    state.vals.push(token);
  }

  function flush(obj) {
    const k = keyFor(obj);
    const state = agg.get(k);
    if (!state) return;
    const line = fmtLine(state);
    if (line) console.log('[RunData] ' + line);
    agg.delete(k);
  }

  function tryHookSetter(className, methodName, sig, onCall) {
    try {
      const C = Java.use(className);
      if (!C[methodName]) return false;

      const ov = C[methodName].overload.apply(C[methodName], sig);

      ov.implementation = function () {
        const ret = ov.apply(this, arguments);

        try {
          onCall(this, arguments);
        } catch (_) {}

        return ret;
      };
      return true;
    } catch (_) {
      return false;
    }
  }

  function hookConcreteRunDataClass(className) {
    if (hookedClasses[className]) return;
    hookedClasses[className] = true;

    const hooked = [];

    // setDataType(dt)
    if (tryHookSetter(
      className,
      'setDataType',
      ['com.theswitchbot.connector.abs.RunDataType'],
      (self, args) => {
        const { s } = getOrInit(self);
        s.dt = args[0] ? args[0].toString() : '?';
        if (PRINT_ON === 'setDataType') flush(self);
      }
    )) hooked.push('setDataType');

    // setValueType(vt)
    if (tryHookSetter(
      className,
      'setValueType',
      ['com.theswitchbot.connector.abs.ValueType'],
      (self, args) => {
        const { s } = getOrInit(self);
        s.vt = args[0] ? args[0].toString() : '?';
        if (PRINT_ON === 'setValueType') flush(self);
      }
    )) hooked.push('setValueType');

    // value setters
    if (tryHookSetter(
      className, 'setIntValue', ['java.lang.Integer'],
      (self, args) => { const { s } = getOrInit(self); maybeAddVal(s, 'i=' + args[0]); }
    )) hooked.push('setIntValue');

    if (tryHookSetter(
      className, 'setBoolValue', ['java.lang.Boolean'],
      (self, args) => { const { s } = getOrInit(self); maybeAddVal(s, 'b=' + args[0]); }
    )) hooked.push('setBoolValue');

    if (tryHookSetter(
      className, 'setLongValue', ['java.lang.Long'],
      (self, args) => { const { s } = getOrInit(self); maybeAddVal(s, 'l=' + args[0]); }
    )) hooked.push('setLongValue');

    if (tryHookSetter(
      className, 'setFloatValue', ['java.lang.Float'],
      (self, args) => { const { s } = getOrInit(self); maybeAddVal(s, 'f=' + args[0]); }
    )) hooked.push('setFloatValue');

    if (tryHookSetter(
      className, 'setStringValue', ['java.lang.String'],
      (self, args) => { const { s } = getOrInit(self); maybeAddVal(s, 's="' + (args[0] || '') + '"'); }
    )) hooked.push('setStringValue');

    if (tryHookSetter(
      className, 'setAnyValue', ['java.lang.Object'],
      (self, args) => {
        const { s } = getOrInit(self);
        maybeAddVal(s, 'a=' + (args[0] ? args[0].toString() : 'null'));
      }
    )) hooked.push('setAnyValue');

    console.log('[+] Hooked RunData class: ' + className +
      (hooked.length ? (' (' + hooked.join(',') + ')') : ' (no setters found)'));
  }

  Parser.getRunData
    .overload('int', 'java.lang.String', '[B', 'com.theswitchbot.common.ble.dto.ScanRecord')
    .implementation = function (rssi, mac, broadcastData, scanRecord) {

      const result = this.getRunData(rssi, mac, broadcastData, scanRecord);

      try {
        for (let i = 0; i < result.size(); i++) {
          const rd = result.get(i);
          hookConcreteRunDataClass(rd.getClass().getName());
        }
      } catch (_) {}

      // Keep one summary line per call
      try {
        console.log('[getRunData] mac=' + mac + ', rssi=' + rssi + ', count=' + result.size());
      } catch (_) {}

      return result;
    };

  console.log('[+] Hook installed: WoPresenceProParser.getRunData (compact RunData lines)');
});
