// chunk: evasion/sleep_jitter
// depends: (none)
// provides: jitter_sleep
// format: jscript

function jitter_sleep(minMs, maxMs) {
    var delay = minMs + Math.floor(Math.random() * (maxMs - minMs));
    WScript.Sleep(delay);
}
