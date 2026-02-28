// hook_presencepro_min_simple.js
'use strict';

Java.perform(function () {

  // ---- helpers ----
  function b2hex(b) { return ('0' + (b & 0xff).toString(16)).slice(-2); }
  function bytesToHex(arr) {
    if (!arr) return '';
    var out = [];
    for (var i = 0; i < arr.length; i++) out.push(b2hex(arr[i]));
    return out.join('');
  }

  function pad(n) { return ('0' + n).slice(-2); }
  function formatEpoch(sec) {
    if (sec === null || sec === undefined) return 'null';
    if (typeof sec !== 'number') { try { sec = parseInt(sec, 10); } catch (_) {} }
    if (!sec || sec <= 0) return '' + sec;

    var ms = (sec > 1e12) ? sec : (sec * 1000);
    var d = new Date(ms);

    return d.getFullYear() + '-' +
      pad(d.getMonth() + 1) + '-' +
      pad(d.getDate()) + ' ' +
      pad(d.getHours()) + ':' +
      pad(d.getMinutes()) + ':' +
      pad(d.getSeconds());
  }

  function getMfg2409Bytes(scanRecord) {
    try {
      if (!scanRecord) return null;
      var sa = scanRecord.getManufacturerSpecificData();
      if (!sa) return null;

      var raw = sa.get(2409);          // byte[] or null
      if (!raw) return null;

      return Java.array('byte', raw);  // Java byte[] -> JS array
    } catch (_) {
      return null;
    }
  }

  function getSeq(mfg2409) {
    try {
      return (mfg2409 && mfg2409.length >= 7) ? (mfg2409[6] & 0xff) : null;
    } catch (_) {
      return null;
    }
  }

  // ---- hooks ----
  var Parser = Java.use('com.theswitchbot.device.protocol.scan.delegate.WoPresenceProParser');
  var RunData = Java.use('com.theswitchbot.connector.abs.RunData');

  Parser.getRunData
    .overload('int', 'java.lang.String', '[B', 'com.theswitchbot.common.ble.dto.ScanRecord')
    .implementation = function (rssi, mac, broadcastData, scanRecord) {

      var result = this.getRunData(rssi, mac, broadcastData, scanRecord);

      var pair = null, last = null, led = null, light = null, move = null, work = null;

      for (var i = 0; i < result.size(); i++) {
        var rd = Java.cast(result.get(i), RunData);
        var type = rd.getDataType().toString();

        if (type === 'WO_PAIR_MODE') pair = rd.getBoolValue();
        else if (type === 'WO_MOTION_SENSOR_LAST_TIME') last = rd.getIntValue();
        else if (type === 'WO_SENSOR_LED') led = rd.getIntValue();
        else if (type === 'WO_MOTION_SENSOR_LIGHT_INTENSITY') light = rd.getIntValue();
        else if (type === 'WO_MOTION_SENSOR_MOVE') move = rd.getIntValue();
        else if (type === 'WO_WORK_MODE') work = rd.getIntValue();
      }

      var mfg2409 = getMfg2409Bytes(scanRecord);
      var seq = getSeq(mfg2409);

      console.log(
        'mac=' + mac +
        ' rssi=' + rssi +
        ' seq=' + seq +
        ' move=' + move +
        ' work=' + work +
        ' light=' + light +
        ' led=' + led +
        ' last=' + formatEpoch(last) +
        ' last_raw=' + last +
        ' pair=' + pair +
        ' adv=' + bytesToHex(broadcastData) +
        (mfg2409 ? (' mfg2409=' + bytesToHex(mfg2409)) : '')
      );

      return result;
    };

  console.log('[+] PresencePro hook installed');
});
