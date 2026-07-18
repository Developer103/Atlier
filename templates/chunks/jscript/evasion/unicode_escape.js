// chunk: evasion/unicode_escape
// depends: (none)
// provides: _d
// format: jscript
// note: Decodes from flat array of hex digit pairs. Each character is stored
//       as two separate hex digits, defeating charcode-array signatures.

function _d(arr) {
    var s = "";
    for (var i = 0; i < arr.length; i += 2) {
        s += String.fromCharCode(parseInt("" + arr[i] + arr[i + 1], 16));
    }
    return s;
}
