Java.perform(function () {
  console.log("[*] Enumerating loaded classes containing 'CmdGenerator'...");

  const hits = [];
  Java.enumerateLoadedClasses({
    onMatch: function (name) {
      if (name.indexOf("CmdGenerator") !== -1) hits.push(name);
    },
    onComplete: function () {
      hits.sort();
      console.log("[*] Found " + hits.length + " loaded class(es):");
      hits.forEach(n => console.log("  " + n));
    }
  });
});
