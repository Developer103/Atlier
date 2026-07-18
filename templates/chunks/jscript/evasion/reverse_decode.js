// chunk: evasion/reverse_decode
// depends: (none)
// provides: _d
// format: jscript
// note: Decodes reversed charcode arrays. Encoded strings are stored
//       backwards, defeating linear pattern scanning.

function _d(arr) {
    var s = "";
    for (var i = arr.length - 1; i >= 0; i--) s += String.fromCharCode(arr[i]);
    return s;
}
