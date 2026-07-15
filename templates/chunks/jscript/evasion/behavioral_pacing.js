// chunk: evasion/behavioral_pacing
// depends: evasion/sleep_jitter
// provides: pace
// format: jscript

function pace(minMs, maxMs) {
    jitter_sleep(minMs, maxMs);
}
